#pragma once

#include "qsafe/audit/audit.hpp"
#include "qsafe/repair/reed_solomon_codec.hpp"

namespace qsafe::repair {

enum class RepairStatus {
  Repaired,
  InvalidRequest,
  InvalidManifest,
  StaleVersion,
  MissingProof,
  CorruptInput,
  Unrecoverable,
  CommitmentMismatch,
  StorageError,
  TargetedAuditFailed
};

struct RepairResult {
  RepairStatus status = RepairStatus::InvalidRequest;
  uint64_t repaired_index = 0;
  uint64_t bytes_read = 0;
  uint64_t repair_bytes = 0;
  std::string error;

  bool repaired() const;
};

RepairResult repairShard(const manifest::Manifest& signed_manifest,
                         const common::Bytes& manifest_signature,
                         const crypto::LiboqsSigner& signer,
                         const common::Bytes& trusted_owner_public_key,
                         const audit::TrustedCheckpoint& checkpoint,
                         storage::CloudStorage& cloud, uint64_t target_index);

}
