#pragma once

#include "qsafe/audit/audit.hpp"
#include "qsafe/repair/commitment_repair.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace qsafe::vault {

struct WorkspaceInfo {
  std::string file_id;
  uint64_t version = 1;
  uint64_t original_length = 0;
  uint64_t source_shard_count = 0;
  uint64_t shard_size = 0;
  manifest::Manifest signed_manifest;
  common::Bytes manifest_signature;
  common::Bytes workspace_signature;
  common::Bytes owner_public_key;
};

std::optional<WorkspaceInfo> ingestFile(const std::filesystem::path& input_path,
                                        const std::filesystem::path& workspace,
                                        std::string& error);
std::optional<WorkspaceInfo> inspectWorkspace(const std::filesystem::path& workspace,
                                              std::string& error);
std::optional<audit::AuditResult> auditFile(const std::filesystem::path& workspace,
                                            uint64_t sample_count, std::string& error);
bool markShardUnavailable(const std::filesystem::path& workspace, uint64_t index,
                          std::string& error);
repair::RepairResult recoverShard(const std::filesystem::path& workspace, uint64_t index);
bool restoreFile(const std::filesystem::path& workspace,
                 const std::filesystem::path& output_path, std::string& error);

}
