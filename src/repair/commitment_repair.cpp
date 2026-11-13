#include "qsafe/repair/commitment_repair.hpp"

#include "qsafe/merkle/merkle_tree.hpp"

#include <algorithm>
#include <limits>

namespace qsafe::repair {

namespace {

RepairResult failure(RepairStatus status, uint64_t index, const std::string& message) {
  RepairResult result;
  result.status = status;
  result.repaired_index = index;
  result.error = message;
  return result;
}

}

bool RepairResult::repaired() const { return status == RepairStatus::Repaired; }

RepairResult repairShard(const manifest::Manifest& signed_manifest,
                         const common::Bytes& manifest_signature,
                         const crypto::LiboqsSigner& signer,
                         const common::Bytes& trusted_owner_public_key,
                         const audit::TrustedCheckpoint& checkpoint,
                         storage::CloudStorage& cloud, uint64_t target_index) {
  if (!manifest::verify(signed_manifest, manifest_signature, signer,
                        trusted_owner_public_key)) {
    return failure(RepairStatus::InvalidManifest, target_index,
                   "manifest signature or encoding is invalid");
  }
  if (checkpoint.file_id != signed_manifest.file_id ||
      checkpoint.version != signed_manifest.version) {
    return failure(RepairStatus::StaleVersion, target_index,
                   "manifest version does not match trusted checkpoint");
  }
  if (target_index >= signed_manifest.shard_count || signed_manifest.data_shards == 0 ||
      signed_manifest.parity_shards == 0) {
    return failure(RepairStatus::InvalidRequest, target_index, "invalid target shard");
  }

  std::string codec_error;
  const auto codec = ReedSolomonCodec::create(signed_manifest.data_shards,
                                               signed_manifest.parity_shards, codec_error);
  if (!codec.has_value()) {
    return failure(RepairStatus::InvalidRequest, target_index, codec_error);
  }
  const uint64_t stripe_width = static_cast<uint64_t>(signed_manifest.data_shards) +
                                signed_manifest.parity_shards;
  if (signed_manifest.shard_count % stripe_width != 0) {
    return failure(RepairStatus::InvalidRequest, target_index,
                   "manifest shard count is not a whole number of stripes");
  }
  const uint64_t stripe_start = target_index - target_index % stripe_width;
  const uint32_t local_target = static_cast<uint32_t>(target_index % stripe_width);
  const auto target_proof = cloud.getPath(signed_manifest.file_id, signed_manifest.version,
                                          target_index);
  if (!target_proof.has_value()) {
    return failure(RepairStatus::MissingProof, target_index,
                   "original proof metadata for target shard is unavailable or malformed");
  }

  std::vector<IndexedShard> available;
  uint64_t bytes_read = 0;
  for (uint32_t local_index = 0; local_index < stripe_width; ++local_index) {
    const uint64_t global_index = stripe_start + local_index;
    if (global_index == target_index) continue;
    const auto stored = cloud.getShard(signed_manifest.file_id, signed_manifest.version,
                                       global_index);
    if (stored.status == storage::ReadStatus::Unavailable) continue;
    if (stored.status != storage::ReadStatus::Available) {
      auto result = failure(RepairStatus::StorageError, target_index,
                            "failed reading a candidate stripe shard");
      result.bytes_read = bytes_read;
      return result;
    }
    if (stored.bytes.size() > std::numeric_limits<uint64_t>::max() - bytes_read) {
      return failure(RepairStatus::InvalidRequest, target_index, "stripe byte count overflow");
    }
    bytes_read += stored.bytes.size();

    const auto proof = cloud.getPath(signed_manifest.file_id, signed_manifest.version,
                                     global_index);
    if (!proof.has_value()) {
      auto result = failure(RepairStatus::MissingProof, target_index,
                            "original proof metadata for a decode input is unavailable");
      result.bytes_read = bytes_read;
      return result;
    }
    const auto leaf = crypto::leafHash(signed_manifest.file_id, signed_manifest.version,
                                       global_index, stored.bytes);
    if (!leaf.has_value() ||
        !merkle::MerkleTree::verify(*leaf, global_index, signed_manifest.shard_count, *proof,
                                    signed_manifest.root)) {
      auto result = failure(RepairStatus::CorruptInput, target_index,
                            "candidate decode input does not match the original signed root");
      result.bytes_read = bytes_read;
      return result;
    }
    available.push_back({local_index, stored.bytes});
  }

  const auto recovered = codec->decodeStripe(available);
  if (!recovered.has_value()) {
    auto result = failure(RepairStatus::Unrecoverable, target_index,
                          "authenticated stripe inputs are insufficient for decoding");
    result.bytes_read = bytes_read;
    return result;
  }
  const auto target = std::find_if(recovered->begin(), recovered->end(),
                                   [local_target](const IndexedShard& shard) {
                                     return shard.index == local_target;
                                   });
  if (target == recovered->end()) {
    auto result = failure(RepairStatus::Unrecoverable, target_index,
                          "codec did not reconstruct the requested shard");
    result.bytes_read = bytes_read;
    return result;
  }

  const auto reconstructed_leaf = crypto::leafHash(signed_manifest.file_id,
                                                     signed_manifest.version, target_index,
                                                     target->bytes);
  if (!reconstructed_leaf.has_value() ||
      !merkle::MerkleTree::verify(*reconstructed_leaf, target_index,
                                  signed_manifest.shard_count, *target_proof,
                                  signed_manifest.root)) {
    auto result = failure(RepairStatus::CommitmentMismatch, target_index,
                          "reconstructed shard does not verify against the original root");
    result.bytes_read = bytes_read;
    return result;
  }

  std::string storage_error;
  if (!cloud.storeRepairedShard(signed_manifest.file_id, signed_manifest.version, target_index,
                                target->bytes, storage_error)) {
    auto result = failure(RepairStatus::StorageError, target_index, storage_error);
    result.bytes_read = bytes_read;
    return result;
  }

  const auto targeted_read = cloud.getShard(signed_manifest.file_id, signed_manifest.version,
                                             target_index);
  const auto targeted_proof = cloud.getPath(signed_manifest.file_id, signed_manifest.version,
                                             target_index);
  if (targeted_read.status != storage::ReadStatus::Available || !targeted_proof.has_value()) {
    cloud.setAvailability(signed_manifest.file_id, signed_manifest.version, target_index,
                          storage::ShardAvailability::Unavailable, storage_error);
    auto result = failure(RepairStatus::TargetedAuditFailed, target_index,
                          "targeted re-audit could not read repaired shard proof data");
    result.bytes_read = bytes_read;
    return result;
  }
  if (targeted_read.bytes.size() > std::numeric_limits<uint64_t>::max() - bytes_read) {
    cloud.setAvailability(signed_manifest.file_id, signed_manifest.version, target_index,
                          storage::ShardAvailability::Unavailable, storage_error);
    return failure(RepairStatus::InvalidRequest, target_index, "repair byte count overflow");
  }
  bytes_read += targeted_read.bytes.size();
  const auto targeted_leaf = crypto::leafHash(signed_manifest.file_id, signed_manifest.version,
                                               target_index, targeted_read.bytes);
  if (!targeted_leaf.has_value() ||
      !merkle::MerkleTree::verify(*targeted_leaf, target_index, signed_manifest.shard_count,
                                  *targeted_proof, signed_manifest.root)) {
    cloud.setAvailability(signed_manifest.file_id, signed_manifest.version, target_index,
                          storage::ShardAvailability::Unavailable, storage_error);
    auto result = failure(RepairStatus::TargetedAuditFailed, target_index,
                          "targeted re-audit rejected repaired shard");
    result.bytes_read = bytes_read;
    return result;
  }

  RepairResult result;
  result.status = RepairStatus::Repaired;
  result.repaired_index = target_index;
  result.bytes_read = bytes_read;
  result.repair_bytes = target->bytes.size();
  return result;
}

}
