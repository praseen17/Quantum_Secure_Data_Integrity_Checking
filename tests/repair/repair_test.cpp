#include "qsafe/audit/audit.hpp"
#include "qsafe/merkle/merkle_tree.hpp"
#include "qsafe/repair/commitment_repair.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>

namespace qsafe::repair {

namespace {

class RepairFixture {
 public:
  RepairFixture(bool consistent_codeword = true) {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    root = std::filesystem::temp_directory_path() /
           ("qsafe-repair-test-" + std::to_string(suffix));
    std::string error;
    cloud = storage::CloudStorage::open(root, error);
    if (!cloud.has_value()) throw std::runtime_error(error);
    signer = crypto::LiboqsSigner::create("ML-DSA-44", error);
    if (!signer.has_value()) throw std::runtime_error(error);
    auto generated = signer->generateKeyPair();
    if (!generated.has_value()) throw std::runtime_error("key generation failed");
    owner_keys = std::move(*generated);
    codec = ReedSolomonCodec::create(4, 2, error);
    if (!codec.has_value()) throw std::runtime_error(error);

    std::vector<common::Bytes> first_data(4, common::Bytes(128));
    std::vector<common::Bytes> second_data(4, common::Bytes(128));
    for (size_t shard = 0; shard < 4; ++shard) {
      for (size_t byte = 0; byte < 128; ++byte) {
        first_data[shard][byte] = static_cast<uint8_t>(shard * 31 + byte * 13 + 5);
        second_data[shard][byte] = static_cast<uint8_t>(shard * 17 + byte * 7 + 9);
      }
    }
    auto first_parity = codec->encodeStripe(first_data);
    auto second_parity = codec->encodeStripe(second_data);
    if (!first_parity.has_value() || !second_parity.has_value()) {
      throw std::runtime_error("parity encoding failed");
    }
    original_shards = first_data;
    original_shards.insert(original_shards.end(), first_parity->begin(), first_parity->end());
    original_shards.insert(original_shards.end(), second_data.begin(), second_data.end());
    original_shards.insert(original_shards.end(), second_parity->begin(), second_parity->end());
    if (!consistent_codeword) original_shards[4][0] ^= 0x55;

    std::vector<crypto::Hash> leaves;
    for (size_t i = 0; i < original_shards.size(); ++i) {
      const auto leaf = crypto::leafHash("repair-file", 9, i, original_shards[i]);
      if (!leaf.has_value()) throw std::runtime_error("leaf hashing failed");
      leaves.push_back(*leaf);
    }
    const auto tree = merkle::MerkleTree::build(leaves);
    if (!tree.has_value()) throw std::runtime_error("Merkle construction failed");
    std::vector<std::vector<crypto::Hash>> paths;
    for (size_t i = 0; i < leaves.size(); ++i) paths.push_back(*tree->path(i));
    if (!cloud->put("repair-file", 9, original_shards, paths, error)) {
      throw std::runtime_error(error);
    }

    signed_manifest.file_id = "repair-file";
    signed_manifest.version = 9;
    signed_manifest.root = tree->root();
    signed_manifest.shard_count = original_shards.size();
    signed_manifest.data_shards = 4;
    signed_manifest.parity_shards = 2;
    signed_manifest.codec = "ISA-L-RS";
    signed_manifest.hash_id = "SHA-256";
    signed_manifest.protocol_version = 1;
    auto signed_value = manifest::sign(signed_manifest, *signer, owner_keys);
    if (!signed_value.has_value()) throw std::runtime_error("manifest signing failed");
    signature = std::move(*signed_value);
  }

  ~RepairFixture() {
    cloud.reset();
    std::filesystem::remove_all(root);
  }

  audit::TrustedCheckpoint checkpoint() const { return {"repair-file", 9}; }

  std::filesystem::path root;
  std::optional<storage::CloudStorage> cloud;
  std::optional<crypto::LiboqsSigner> signer;
  crypto::SigningKeyPair owner_keys;
  std::optional<ReedSolomonCodec> codec;
  manifest::Manifest signed_manifest;
  common::Bytes signature;
  std::vector<common::Bytes> original_shards;
};

common::Bytes encodeProof(const std::vector<crypto::Hash>& proof) {
  common::CanonicalWriter writer;
  writer.writeU32(static_cast<uint32_t>(proof.size()));
  for (const auto& hash : proof) writer.writeBytes(hash.data(), hash.size());
  return writer.data();
}

RepairResult repair(RepairFixture& fixture, uint64_t index) {
  return repairShard(fixture.signed_manifest, fixture.signature, *fixture.signer,
                     fixture.owner_keys.public_key, fixture.checkpoint(), *fixture.cloud, index);
}

}

TEST(CommitmentRepair, RepairsMissingShardAgainstOriginalRootAndVersion) {
  RepairFixture fixture;
  const auto original_root = fixture.signed_manifest.root;
  const auto original_version = fixture.signed_manifest.version;
  std::string error;
  ASSERT_TRUE(fixture.cloud->setAvailability("repair-file", 9, 2,
                                             storage::ShardAvailability::Unavailable, error))
      << error;

  const auto result = repair(fixture, 2);
  EXPECT_EQ(result.status, RepairStatus::Repaired);
  EXPECT_EQ(result.repaired_index, 2U);
  EXPECT_EQ(result.bytes_read, 6 * 128U);
  EXPECT_EQ(result.repair_bytes, 128U);
  EXPECT_EQ(fixture.signed_manifest.root, original_root);
  EXPECT_EQ(fixture.signed_manifest.version, original_version);
  const auto restored = fixture.cloud->getShard("repair-file", 9, 2);
  ASSERT_EQ(restored.status, storage::ReadStatus::Available);
  EXPECT_EQ(restored.bytes, fixture.original_shards[2]);
}

TEST(CommitmentRepair, RepairsCorruptedTargetWithoutUsingItAsDecodeInput) {
  RepairFixture fixture;
  std::string error;
  auto corrupted = fixture.original_shards[2];
  corrupted[4] ^= 0x80;
  ASSERT_TRUE(fixture.cloud->injectFaultShardBytes("repair-file", 9, 2, corrupted, error))
      << error;
  const auto result = repair(fixture, 2);
  EXPECT_EQ(result.status, RepairStatus::Repaired);
  EXPECT_EQ(fixture.cloud->getShard("repair-file", 9, 2).bytes, fixture.original_shards[2]);
}

TEST(AdversarialRepair, RejectsRepairAgainstAChangedSignedRoot) {
  RepairFixture fixture;
  auto replacement_manifest = fixture.signed_manifest;
  replacement_manifest.root[0] ^= 0x01;
  const auto replacement_signature = manifest::sign(replacement_manifest, *fixture.signer,
                                                     fixture.owner_keys);
  ASSERT_TRUE(replacement_signature.has_value());
  std::string error;
  ASSERT_TRUE(fixture.cloud->setAvailability("repair-file", 9, 2,
      storage::ShardAvailability::Unavailable, error)) << error;
  const auto result = repairShard(replacement_manifest, *replacement_signature, *fixture.signer,
      fixture.owner_keys.public_key, fixture.checkpoint(), *fixture.cloud, 2);
  EXPECT_EQ(result.status, RepairStatus::CorruptInput);
  EXPECT_EQ(fixture.cloud->getShard("repair-file", 9, 2).status,
            storage::ReadStatus::Unavailable);
}

TEST(CommitmentRepair, RejectsPoisonedDataOrParityBeforeDecoding) {
  for (const uint64_t poisoned_index : {1U, 4U}) {
    RepairFixture fixture;
    std::string error;
    ASSERT_TRUE(fixture.cloud->setAvailability("repair-file", 9, 0,
                                               storage::ShardAvailability::Unavailable, error))
        << error;
    auto poisoned = fixture.original_shards[poisoned_index];
    poisoned[0] ^= 0xff;
    ASSERT_TRUE(fixture.cloud->injectFaultShardBytes("repair-file", 9, poisoned_index, poisoned,
                                                     error))
        << error;
    const auto result = repair(fixture, 0);
    EXPECT_EQ(result.status, RepairStatus::CorruptInput);
    EXPECT_EQ(fixture.cloud->getShard("repair-file", 9, 0).status,
              storage::ReadStatus::Unavailable);
  }
}

TEST(CommitmentRepair, FailsClosedWhenProofMetadataIsMissingTruncatedOrForWrongIndex) {
  for (const auto& bad_proof : {common::Bytes{}, common::Bytes{0, 0}}) {
    RepairFixture fixture;
    std::string error;
    ASSERT_TRUE(fixture.cloud->setAvailability("repair-file", 9, 3,
                                               storage::ShardAvailability::Unavailable, error))
        << error;
    ASSERT_TRUE(fixture.cloud->injectFaultProofBytes("repair-file", 9, 3, bad_proof, error))
        << error;
    EXPECT_EQ(repair(fixture, 3).status, RepairStatus::MissingProof);
  }

  RepairFixture fixture;
  std::string error;
  ASSERT_TRUE(fixture.cloud->setAvailability("repair-file", 9, 3,
                                             storage::ShardAvailability::Unavailable, error))
      << error;
  const auto wrong_proof = fixture.cloud->getPath("repair-file", 9, 4);
  ASSERT_TRUE(wrong_proof.has_value());
  ASSERT_TRUE(fixture.cloud->injectFaultProofBytes("repair-file", 9, 3, encodeProof(*wrong_proof),
                                                   error))
      << error;
  EXPECT_EQ(repair(fixture, 3).status, RepairStatus::CommitmentMismatch);

  RepairFixture input_proof_fixture;
  ASSERT_TRUE(input_proof_fixture.cloud->setAvailability("repair-file", 9, 0,
                                                         storage::ShardAvailability::Unavailable,
                                                         error));
  ASSERT_TRUE(input_proof_fixture.cloud->injectFaultProofBytes("repair-file", 9, 1,
                                                               common::Bytes{}, error));
  EXPECT_EQ(repair(input_proof_fixture, 0).status, RepairStatus::MissingProof);
}

TEST(CommitmentRepair, RejectsProofFromAnotherVersionAndInconsistentCodeword) {
  RepairFixture fixture;
  std::string error;
  ASSERT_TRUE(fixture.cloud->setAvailability("repair-file", 9, 1,
                                             storage::ShardAvailability::Unavailable, error))
      << error;
  std::vector<crypto::Hash> new_leaves;
  for (size_t i = 0; i < fixture.original_shards.size(); ++i) {
    const auto leaf = crypto::leafHash("repair-file", 10, i, fixture.original_shards[i]);
    ASSERT_TRUE(leaf.has_value());
    new_leaves.push_back(*leaf);
  }
  const auto newer_tree = merkle::MerkleTree::build(new_leaves);
  ASSERT_TRUE(newer_tree.has_value());
  std::vector<std::vector<crypto::Hash>> newer_paths;
  for (size_t i = 0; i < new_leaves.size(); ++i) {
    newer_paths.push_back(*newer_tree->path(i));
  }
  ASSERT_TRUE(fixture.cloud->put("repair-file", 10, fixture.original_shards, newer_paths, error))
      << error;
  const auto other_version_proof = fixture.cloud->getPath("repair-file", 10, 1);
  ASSERT_TRUE(other_version_proof.has_value());
  ASSERT_TRUE(fixture.cloud->injectFaultProofBytes("repair-file", 9, 1,
                                                   encodeProof(*other_version_proof), error))
      << error;
  EXPECT_EQ(repair(fixture, 1).status, RepairStatus::CommitmentMismatch);

  RepairFixture inconsistent(false);
  ASSERT_TRUE(inconsistent.cloud->setAvailability("repair-file", 9, 0,
                                                  storage::ShardAvailability::Unavailable, error))
      << error;
  EXPECT_EQ(repair(inconsistent, 0).status, RepairStatus::CommitmentMismatch);
}

TEST(CommitmentRepair, ReportsUnrecoverableStripeAndRejectsStaleManifest) {
  RepairFixture fixture;
  std::string error;
  for (const uint64_t index : {0U, 1U, 2U}) {
    ASSERT_TRUE(fixture.cloud->setAvailability("repair-file", 9, index,
                                               storage::ShardAvailability::Unavailable, error))
        << error;
  }
  EXPECT_EQ(repair(fixture, 0).status, RepairStatus::Unrecoverable);
  EXPECT_EQ(repairShard(fixture.signed_manifest, fixture.signature, *fixture.signer,
                        fixture.owner_keys.public_key, {"repair-file", 8}, *fixture.cloud, 0)
                .status,
            RepairStatus::StaleVersion);
}

}
