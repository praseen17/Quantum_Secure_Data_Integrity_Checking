#pragma once

#include "qsafe/manifest/manifest.hpp"
#include "qsafe/storage/cloud_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace qsafe::audit {

struct TrustedCheckpoint {
  std::string file_id;
  uint64_t version = 0;
};

struct Challenge {
  std::string file_id;
  uint64_t version = 0;
  common::Bytes nonce;
  std::vector<uint64_t> indices;
  crypto::Hash id{};
};

struct AuditedShard {
  uint64_t index = 0;
  storage::ReadStatus status = storage::ReadStatus::Unavailable;
  common::Bytes bytes;
  std::vector<crypto::Hash> proof;
};

struct AuditResponse {
  crypto::Hash challenge_id{};
  common::Bytes nonce;
  uint64_t version = 0;
  std::vector<AuditedShard> shards;
};

enum class ShardResultCode { Verified, Corrupt, Unavailable, Inconclusive };

struct ShardResult {
  uint64_t index = 0;
  ShardResultCode result = ShardResultCode::Inconclusive;
};

struct AuditResult {
  bool manifest_valid = false;
  bool checkpoint_valid = false;
  bool challenge_valid = false;
  std::vector<ShardResult> shards;

  bool allVerified() const;
};

std::optional<double> detectionProbability(uint64_t population, uint64_t corrupted,
                                           uint64_t sample_count);
std::optional<uint64_t> baselineSampleSize(uint64_t population, double corruption_fraction,
                                           double target_detection_probability);
std::optional<Challenge> createChallenge(const std::string& file_id, uint64_t version,
                                         uint64_t shard_count, uint64_t sample_count,
                                         std::string& error);
std::optional<Challenge> extendChallenge(const Challenge& baseline,
                                         const std::vector<uint64_t>& supplemental_indices,
                                         std::string& error);
AuditResponse makeResponse(const Challenge& challenge, const storage::CloudStorage& cloud);
AuditResult verifyResponse(const manifest::Manifest& signed_manifest,
                           const common::Bytes& manifest_signature,
                           const crypto::LiboqsSigner& signer,
                           const common::Bytes& trusted_owner_public_key,
                           const TrustedCheckpoint& checkpoint, const Challenge& challenge,
                           const AuditResponse& response);

}
