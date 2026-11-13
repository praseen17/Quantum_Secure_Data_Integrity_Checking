#include "qsafe/audit/audit.hpp"
#include "qsafe/merkle/merkle_tree.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>

namespace qsafe::audit {

namespace {

struct Fixture {
  std::filesystem::path root;
  std::optional<storage::CloudStorage> cloud;
  std::optional<crypto::LiboqsSigner> signer;
  crypto::SigningKeyPair owner_keys;
  manifest::Manifest signed_manifest;
  common::Bytes signature;

  Fixture() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    root = std::filesystem::temp_directory_path() /
           ("qsafe-audit-test-" + std::to_string(suffix));
    std::string error;
    cloud = storage::CloudStorage::open(root, error);
    if (!cloud.has_value()) throw std::runtime_error(error);
    signer = crypto::LiboqsSigner::create("ML-DSA-44", error);
    if (!signer.has_value()) throw std::runtime_error(error);
    auto generated_keys = signer->generateKeyPair();
    if (!generated_keys.has_value()) throw std::runtime_error("key generation failed");
    owner_keys = std::move(*generated_keys);

    const std::vector<common::Bytes> shards = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    std::vector<crypto::Hash> leaves;
    for (size_t i = 0; i < shards.size(); ++i) {
      const auto leaf = crypto::leafHash("audit-file", 7, i, shards[i]);
      if (!leaf.has_value()) throw std::runtime_error("leaf hash failed");
      leaves.push_back(*leaf);
    }
    const auto tree = merkle::MerkleTree::build(leaves);
    if (!tree.has_value()) throw std::runtime_error("Merkle build failed");
    std::vector<std::vector<crypto::Hash>> paths;
    for (size_t i = 0; i < leaves.size(); ++i) paths.push_back(*tree->path(i));
    if (!cloud->put("audit-file", 7, shards, paths, error)) throw std::runtime_error(error);

    signed_manifest.file_id = "audit-file";
    signed_manifest.version = 7;
    signed_manifest.root = tree->root();
    signed_manifest.shard_count = shards.size();
    signed_manifest.data_shards = 1;
    signed_manifest.parity_shards = 2;
    signed_manifest.codec = "ISA-L-RS";
    signed_manifest.hash_id = "SHA-256";
    signed_manifest.protocol_version = 1;
    auto signed_value = manifest::sign(signed_manifest, *signer, owner_keys);
    if (!signed_value.has_value()) throw std::runtime_error("manifest signing failed");
    signature = std::move(*signed_value);
  }

  ~Fixture() {
    cloud.reset();
    std::filesystem::remove_all(root);
  }
};

AuditResult auditAll(Fixture& fixture, const TrustedCheckpoint& checkpoint,
                     AuditResponse* response_out = nullptr) {
  std::string error;
  auto challenge = createChallenge("audit-file", 7, 3, 3, error);
  if (!challenge.has_value()) throw std::runtime_error(error);
  auto response = makeResponse(*challenge, *fixture.cloud);
  if (response_out != nullptr) *response_out = response;
  return verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                        fixture.owner_keys.public_key, checkpoint, *challenge, response);
}

}

TEST(AuditIntegration, CompletesSignedSmallFileAudit) {
  Fixture fixture;
  const auto result = auditAll(fixture, {"audit-file", 7});
  EXPECT_TRUE(result.manifest_valid);
  EXPECT_TRUE(result.checkpoint_valid);
  EXPECT_TRUE(result.challenge_valid);
  ASSERT_EQ(result.shards.size(), 3U);
  for (const auto& shard : result.shards) EXPECT_EQ(shard.result, ShardResultCode::Verified);
}

TEST(AuditIntegration, DetectsModifiedAndUnavailableShards) {
  Fixture fixture;
  AuditResponse response;
  std::string error;
  auto challenge = createChallenge("audit-file", 7, 3, 3, error);
  ASSERT_TRUE(challenge.has_value()) << error;
  response = makeResponse(*challenge, *fixture.cloud);
  ASSERT_FALSE(response.shards.empty());
  response.shards[0].bytes[0] ^= 0xff;
  auto result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                               fixture.owner_keys.public_key, {"audit-file", 7}, *challenge,
                               response);
  EXPECT_EQ(result.shards[0].result, ShardResultCode::Corrupt);

  ASSERT_TRUE(fixture.cloud->setAvailability("audit-file", 7, challenge->indices[1],
                                             storage::ShardAvailability::Unavailable, error))
      << error;
  response = makeResponse(*challenge, *fixture.cloud);
  result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                          fixture.owner_keys.public_key, {"audit-file", 7}, *challenge, response);
  EXPECT_EQ(result.shards[1].result, ShardResultCode::Unavailable);
}

TEST(AuditIntegration, RejectsOldNonceStaleVersionAndReorderedIndices) {
  Fixture fixture;
  std::string error;
  auto challenge = createChallenge("audit-file", 7, 3, 3, error);
  ASSERT_TRUE(challenge.has_value()) << error;
  auto response = makeResponse(*challenge, *fixture.cloud);

  response.nonce[0] ^= 1;
  auto result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                               fixture.owner_keys.public_key, {"audit-file", 7}, *challenge,
                               response);
  EXPECT_FALSE(result.challenge_valid);

  response = makeResponse(*challenge, *fixture.cloud);
  result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                          fixture.owner_keys.public_key, {"audit-file", 6}, *challenge, response);
  EXPECT_FALSE(result.checkpoint_valid);

  std::swap(response.shards[0], response.shards[1]);
  result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                          fixture.owner_keys.public_key, {"audit-file", 7}, *challenge, response);
  EXPECT_FALSE(result.challenge_valid);
}

TEST(AdversarialAudit, RejectsSwappedPayloadsReplayAgainstNewChallengeAndProoflessSuccess) {
  Fixture fixture;
  std::string error;
  auto first_challenge = createChallenge("audit-file", 7, 3, 3, error);
  ASSERT_TRUE(first_challenge.has_value()) << error;
  auto response = makeResponse(*first_challenge, *fixture.cloud);

  std::swap(response.shards[0].bytes, response.shards[1].bytes);
  auto result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                               fixture.owner_keys.public_key, {"audit-file", 7},
                               *first_challenge, response);
  ASSERT_EQ(result.shards.size(), 3U);
  EXPECT_EQ(result.shards[0].result, ShardResultCode::Corrupt);
  EXPECT_EQ(result.shards[1].result, ShardResultCode::Corrupt);

  response = makeResponse(*first_challenge, *fixture.cloud);
  auto second_challenge = createChallenge("audit-file", 7, 3, 2, error);
  ASSERT_TRUE(second_challenge.has_value()) << error;
  result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                          fixture.owner_keys.public_key, {"audit-file", 7},
                          *second_challenge, response);
  EXPECT_FALSE(result.challenge_valid);

  response = makeResponse(*first_challenge, *fixture.cloud);
  response.shards[0].proof.clear();
  result = verifyResponse(fixture.signed_manifest, fixture.signature, *fixture.signer,
                          fixture.owner_keys.public_key, {"audit-file", 7},
                          *first_challenge, response);
  EXPECT_EQ(result.shards[0].result, ShardResultCode::Corrupt);
  EXPECT_FALSE(result.allVerified());
}

}
