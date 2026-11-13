#include "qsafe/audit/risk_sampling.hpp"
#include "qsafe/merkle/merkle_tree.hpp"
#include "qsafe/receipts/audit_log.hpp"
#include "qsafe/repair/reed_solomon_codec.hpp"
#include "qsafe/storage/chunker.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
  namespace fs = std::filesystem;
  using namespace qsafe;
  const fs::path root = argc > 1 ? fs::path(argv[1])
                                 : fs::temp_directory_path() /
                                       ("qsafe-demo-" + std::to_string(
                                           std::chrono::steady_clock::now()
                                               .time_since_epoch()
                                               .count()));
  std::string error;
  auto cloud = storage::CloudStorage::open(root / "cloud", error);
  auto owner_signer = crypto::LiboqsSigner::create("ML-DSA-44", error);
  auto auditor_signer = crypto::LiboqsSigner::create("ML-DSA-44", error);
  if (!cloud || !owner_signer || !auditor_signer) {
    std::cerr << "initialization failed: " << error << '\n';
    return 1;
  }
  auto owner_keys = owner_signer->generateKeyPair();
  auto auditor_keys = auditor_signer->generateKeyPair();
  if (!owner_keys || !auditor_keys) {
    std::cerr << "ML-DSA key generation failed\n";
    return 1;
  }

  common::Bytes input(256 * 1024);
  for (size_t i = 0; i < input.size(); ++i) input[i] = static_cast<uint8_t>((i * 31) & 0xff);
  const auto chunked = storage::FileChunker::split(input);
  if (!chunked) {
    std::cerr << "file chunking failed\n";
    return 1;
  }
  std::string codec_error;
  const auto codec = repair::ReedSolomonCodec::create(4, 2, codec_error);
  if (!codec) {
    std::cerr << "Reed-Solomon configuration failed: " << codec_error << '\n';
    return 1;
  }
  auto shards = chunked->shards;
  const auto parity = codec->encodeStripe(chunked->shards);
  if (!parity) {
    std::cerr << "Reed-Solomon encoding failed\n";
    return 1;
  }
  shards.insert(shards.end(), parity->begin(), parity->end());

  const std::string file_id = "demo-file";
  constexpr uint64_t version = 1;
  std::vector<crypto::Hash> leaves;
  for (size_t index = 0; index < shards.size(); ++index) {
    const auto leaf = crypto::leafHash(file_id, version, index, shards[index]);
    if (!leaf) {
      std::cerr << "leaf hashing failed\n";
      return 1;
    }
    leaves.push_back(*leaf);
  }
  const auto tree = merkle::MerkleTree::build(leaves);
  if (!tree) {
    std::cerr << "Merkle construction failed\n";
    return 1;
  }
  std::vector<std::vector<crypto::Hash>> paths;
  for (size_t index = 0; index < leaves.size(); ++index) paths.push_back(*tree->path(index));
  if (!cloud->put(file_id, version, shards, paths, error)) {
    std::cerr << "cloud ingest failed: " << error << '\n';
    return 1;
  }

  manifest::Manifest signed_manifest;
  signed_manifest.file_id = file_id;
  signed_manifest.version = version;
  signed_manifest.root = tree->root();
  signed_manifest.shard_count = shards.size();
  signed_manifest.data_shards = 4;
  signed_manifest.parity_shards = 2;
  signed_manifest.codec = "ISA-L-RS";
  signed_manifest.hash_id = "SHA-256";
  signed_manifest.protocol_version = 1;
  const auto manifest_signature = manifest::sign(signed_manifest, *owner_signer, *owner_keys);
  const auto baseline = audit::createChallenge(file_id, version, leaves.size(), leaves.size(), error);
  if (!manifest_signature || !baseline) {
    std::cerr << "manifest or challenge creation failed: " << error << '\n';
    return 1;
  }
  std::vector<audit::RiskCounts> risks((leaves.size() + 5) / 6);
  if (!risks.empty()) risks.back().failures = 1;
  audit::RiskConfig risk_config;
  const auto challenge = audit::selectSupplemental(*baseline, leaves.size(), 6, risks, 0,
                                                     risk_config, error);
  if (!challenge) {
    std::cerr << "risk sampling failed: " << error << '\n';
    return 1;
  }
  const auto response = audit::makeResponse(*challenge, *cloud);
  const auto result = audit::verifyResponse(signed_manifest, *manifest_signature, *owner_signer,
                                             owner_keys->public_key, {file_id, version},
                                             *challenge, response);
  if (!result.manifest_valid || !result.checkpoint_valid || !result.challenge_valid ||
      !result.allVerified()) {
    std::cerr << "audit failed closed\n";
    return 1;
  }

  auto log = receipts::AuditLog::open(root / "receipts.sqlite", error);
  if (!log) {
    std::cerr << "receipt log open failed: " << error << '\n';
    return 1;
  }
  for (const auto& shard_result : result.shards) {
    receipts::Receipt receipt;
    receipt.file_id = file_id;
    receipt.version = version;
    receipt.challenge_id = challenge->id;
    receipt.nonce = challenge->nonce;
    receipt.shard_index = shard_result.index;
    receipt.stripe_index = shard_result.index / 6;
    receipt.result = receipts::VerificationOutcome::Verified;
    receipt.original_root = signed_manifest.root;
    if (!log->append(receipt, *auditor_signer, *auditor_keys, root / "checkpoint.bin", error)) {
      std::cerr << "receipt append failed: " << error << '\n';
      return 1;
    }
  }
  if (!log->verify(root / "checkpoint.bin", *auditor_signer, auditor_keys->public_key, error)) {
    std::cerr << "receipt checkpoint verification failed: " << error << '\n';
    return 1;
  }
  std::cout << "Q-SAFE demo passed: " << input.size() << " bytes, " << result.shards.size()
            << " verified shards, signed manifest, signed receipts, and verified checkpoint.\n"
            << "Artifacts: " << root << '\n';
  return 0;
}
