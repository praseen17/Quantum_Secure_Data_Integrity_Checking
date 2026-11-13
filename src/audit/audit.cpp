#include "qsafe/audit/audit.hpp"

#include "qsafe/merkle/merkle_tree.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cfloat>
#include <limits>
#include <set>
#include <utility>

namespace qsafe::audit {

namespace {

constexpr size_t kNonceSize = 32;
constexpr uint64_t kMaximumSampleCount = 1000000;

long double logChoose(uint64_t population, uint64_t selected) {
  const uint64_t smaller = std::min(selected, population - selected);
  return std::lgammal(static_cast<long double>(population) + 1.0L) -
         std::lgammal(static_cast<long double>(smaller) + 1.0L) -
         std::lgammal(static_cast<long double>(population - smaller) + 1.0L);
}

std::optional<uint64_t> randomBelow(uint64_t bound) {
  if (bound == 0) return std::nullopt;
  const uint64_t threshold = (uint64_t{0} - bound) % bound;
  while (true) {
    std::array<uint8_t, sizeof(uint64_t)> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) return std::nullopt;
    uint64_t value = 0;
    for (const uint8_t byte : bytes) value = (value << 8) | byte;
    if (value >= threshold) return value % bound;
  }
}

std::optional<crypto::Hash> challengeId(const std::string& file_id, uint64_t version,
                                        const common::Bytes& nonce,
                                        const std::vector<uint64_t>& indices) {
  if (indices.size() > std::numeric_limits<uint32_t>::max()) return std::nullopt;
  common::CanonicalWriter writer;
  if (!writer.writeString("QSAFE-CHALLENGE-v1") || !writer.writeString(file_id) ||
      !writer.writeU64(version) || !writer.writeBytes(nonce) ||
      !writer.writeU32(static_cast<uint32_t>(indices.size()))) {
    return std::nullopt;
  }
  for (const uint64_t index : indices) {
    if (!writer.writeU64(index)) return std::nullopt;
  }
  return crypto::sha256(writer.data());
}

bool validChallenge(const Challenge& challenge, uint64_t shard_count) {
  if (challenge.file_id.empty() || !common::isValidUtf8(challenge.file_id) ||
      challenge.version == 0 || challenge.nonce.size() != kNonceSize ||
      challenge.indices.empty() || challenge.indices.size() > kMaximumSampleCount ||
      challenge.indices.size() > shard_count) {
    return false;
  }
  std::set<uint64_t> unique_indices;
  for (const uint64_t index : challenge.indices) {
    if (index >= shard_count || !unique_indices.insert(index).second) return false;
  }
  const auto expected_id = challengeId(challenge.file_id, challenge.version, challenge.nonce,
                                       challenge.indices);
  return expected_id.has_value() && *expected_id == challenge.id;
}

bool validChallengeIdentity(const Challenge& challenge) {
  if (challenge.file_id.empty() || challenge.file_id.size() > 1024 ||
      !common::isValidUtf8(challenge.file_id) || challenge.version == 0 ||
      challenge.nonce.size() != kNonceSize || challenge.indices.empty() ||
      challenge.indices.size() > kMaximumSampleCount) {
    return false;
  }
  std::set<uint64_t> unique_indices(challenge.indices.begin(), challenge.indices.end());
  if (unique_indices.size() != challenge.indices.size()) return false;
  const auto expected_id = challengeId(challenge.file_id, challenge.version, challenge.nonce,
                                       challenge.indices);
  return expected_id.has_value() && *expected_id == challenge.id;
}

}

std::optional<double> detectionProbability(uint64_t population, uint64_t corrupted,
                                           uint64_t sample_count) {
  if (population == 0 || corrupted > population || sample_count > population) {
    return std::nullopt;
  }
  if (corrupted == 0 || sample_count == 0) return 0.0;
  if (sample_count > population - corrupted) return 1.0;
  const long double log_no_detection = logChoose(population - corrupted, sample_count) -
                                       logChoose(population, sample_count);
  long double probability = -std::expm1(log_no_detection);
  probability = std::max(0.0L, std::min(1.0L, probability));
  return static_cast<double>(probability);
}

std::optional<uint64_t> baselineSampleSize(uint64_t population, double corruption_fraction,
                                           double target_detection_probability) {
  if (population == 0 || !std::isfinite(corruption_fraction) ||
      !std::isfinite(target_detection_probability) || corruption_fraction <= 0.0 ||
      corruption_fraction > 1.0 || target_detection_probability <= 0.0 ||
      target_detection_probability >= 1.0) {
    return std::nullopt;
  }
  const long double product = static_cast<long double>(corruption_fraction) * population;
  const long double rounding_tolerance =
      4.0L * DBL_EPSILON * std::max(1.0L, std::abs(product));
  if (rounding_tolerance >= 0.25L) return std::nullopt;
  const long double minimum_corrupted = std::ceil(product - rounding_tolerance);
  if (minimum_corrupted < 1.0L || minimum_corrupted > population) return std::nullopt;
  const auto corrupted = static_cast<uint64_t>(minimum_corrupted);
  uint64_t low = 0;
  uint64_t high = population;
  while (low < high) {
    const uint64_t middle = low + (high - low) / 2;
    const auto probability = detectionProbability(population, corrupted, middle);
    if (!probability.has_value()) return std::nullopt;
    if (*probability >= target_detection_probability) {
      high = middle;
    } else {
      low = middle + 1;
    }
  }
  return low;
}

std::optional<Challenge> createChallenge(const std::string& file_id, uint64_t version,
                                         uint64_t shard_count, uint64_t sample_count,
                                         std::string& error) {
  if (file_id.empty() || file_id.size() > 1024 || !common::isValidUtf8(file_id) || version == 0 ||
      shard_count == 0 || sample_count == 0 || sample_count > shard_count ||
      sample_count > kMaximumSampleCount) {
    error = "invalid challenge parameters";
    return std::nullopt;
  }

  Challenge challenge;
  challenge.file_id = file_id;
  challenge.version = version;
  challenge.nonce.resize(kNonceSize);
  if (RAND_bytes(challenge.nonce.data(), static_cast<int>(challenge.nonce.size())) != 1) {
    error = "operating system CSPRNG failed";
    return std::nullopt;
  }

  std::set<uint64_t> selected;
  for (uint64_t next = shard_count - sample_count; next < shard_count; ++next) {
    const auto candidate = randomBelow(next + 1);
    if (!candidate.has_value()) {
      error = "operating system CSPRNG failed";
      return std::nullopt;
    }
    if (!selected.insert(*candidate).second) selected.insert(next);
  }
  challenge.indices.assign(selected.begin(), selected.end());
  for (size_t remaining = challenge.indices.size(); remaining > 1; --remaining) {
    const auto target = randomBelow(remaining);
    if (!target.has_value()) {
      error = "operating system CSPRNG failed";
      return std::nullopt;
    }
    std::swap(challenge.indices[remaining - 1],
              challenge.indices[static_cast<size_t>(*target)]);
  }

  const auto id = challengeId(file_id, version, challenge.nonce, challenge.indices);
  if (!id.has_value()) {
    error = "challenge encoding failed";
    return std::nullopt;
  }
  challenge.id = *id;
  error.clear();
  return challenge;
}

std::optional<Challenge> extendChallenge(const Challenge& baseline,
                                         const std::vector<uint64_t>& supplemental_indices,
                                         std::string& error) {
  if (!validChallengeIdentity(baseline) ||
      supplemental_indices.size() > kMaximumSampleCount - baseline.indices.size()) {
    error = "invalid baseline challenge or supplemental count";
    return std::nullopt;
  }
  std::set<uint64_t> selected(baseline.indices.begin(), baseline.indices.end());
  Challenge extended = baseline;
  for (const uint64_t index : supplemental_indices) {
    if (!selected.insert(index).second) {
      error = "supplemental challenge contains a duplicate index";
      return std::nullopt;
    }
    extended.indices.push_back(index);
  }
  if (supplemental_indices.empty()) {
    error.clear();
    return baseline;
  }
  const auto id = challengeId(extended.file_id, extended.version, extended.nonce,
                              extended.indices);
  if (!id.has_value()) {
    error = "extended challenge encoding failed";
    return std::nullopt;
  }
  extended.id = *id;
  error.clear();
  return extended;
}

AuditResponse makeResponse(const Challenge& challenge, const storage::CloudStorage& cloud) {
  AuditResponse response;
  response.challenge_id = challenge.id;
  response.nonce = challenge.nonce;
  response.version = challenge.version;
  response.shards.reserve(challenge.indices.size());
  for (const uint64_t index : challenge.indices) {
    AuditedShard shard;
    shard.index = index;
    const auto stored = cloud.getShard(challenge.file_id, challenge.version, index);
    shard.status = stored.status;
    shard.bytes = stored.bytes;
    if (stored.status == storage::ReadStatus::Available) {
      const auto proof = cloud.getPath(challenge.file_id, challenge.version, index);
      if (proof.has_value()) {
        shard.proof = *proof;
      } else {
        shard.status = storage::ReadStatus::Error;
      }
    }
    response.shards.push_back(std::move(shard));
  }
  return response;
}

AuditResult verifyResponse(const manifest::Manifest& signed_manifest,
                           const common::Bytes& manifest_signature,
                           const crypto::LiboqsSigner& signer,
                           const common::Bytes& trusted_owner_public_key,
                           const TrustedCheckpoint& checkpoint, const Challenge& challenge,
                           const AuditResponse& response) {
  AuditResult result;
  result.manifest_valid = manifest::verify(signed_manifest, manifest_signature, signer,
                                           trusted_owner_public_key);
  result.checkpoint_valid = checkpoint.file_id == signed_manifest.file_id &&
                            checkpoint.version == signed_manifest.version &&
                            signed_manifest.version > 0;
  result.challenge_valid = validChallenge(challenge, signed_manifest.shard_count) &&
                           challenge.file_id == signed_manifest.file_id &&
                           challenge.version == signed_manifest.version &&
                           response.challenge_id == challenge.id &&
                           response.nonce == challenge.nonce &&
                           response.version == challenge.version &&
                           response.shards.size() == challenge.indices.size();

  if (result.challenge_valid) {
    for (size_t i = 0; i < challenge.indices.size(); ++i) {
      if (response.shards[i].index != challenge.indices[i]) {
        result.challenge_valid = false;
        break;
      }
    }
  }

  if (!result.manifest_valid || !result.checkpoint_valid || !result.challenge_valid) {
    for (const uint64_t index : challenge.indices) {
      result.shards.push_back({index, ShardResultCode::Inconclusive});
    }
    return result;
  }

  for (const auto& shard : response.shards) {
    if (shard.status == storage::ReadStatus::Unavailable) {
      result.shards.push_back({shard.index, ShardResultCode::Unavailable});
      continue;
    }
    if (shard.status != storage::ReadStatus::Available) {
      result.shards.push_back({shard.index, ShardResultCode::Inconclusive});
      continue;
    }
    const auto leaf = crypto::leafHash(signed_manifest.file_id, signed_manifest.version,
                                       shard.index, shard.bytes);
    if (!leaf.has_value() ||
        !merkle::MerkleTree::verify(*leaf, shard.index, signed_manifest.shard_count, shard.proof,
                                    signed_manifest.root)) {
      result.shards.push_back({shard.index, ShardResultCode::Corrupt});
      continue;
    }
    result.shards.push_back({shard.index, ShardResultCode::Verified});
  }
  return result;
}

bool AuditResult::allVerified() const {
  return manifest_valid && checkpoint_valid && challenge_valid &&
         std::all_of(shards.begin(), shards.end(), [](const ShardResult& shard) {
           return shard.result == ShardResultCode::Verified;
         });
}

}
