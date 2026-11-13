#include "qsafe/vault/workspace.hpp"

#include "qsafe/crypto/hash.hpp"

#include <charconv>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <utility>

namespace {

bool parseUnsigned(const char* text, uint64_t& value) {
  const std::string input(text == nullptr ? "" : text);
  if (input.empty()) return false;
  const auto parsed = std::from_chars(input.data(), input.data() + input.size(), value);
  return parsed.ec == std::errc{} && parsed.ptr == input.data() + input.size();
}

std::string jsonEscape(const std::string& text) {
  std::string escaped;
  for (const unsigned char ch : text) {
    switch (ch) {
      case '"': escaped += "\\\""; break;
      case '\\': escaped += "\\\\"; break;
      case '\n': escaped += "\\n"; break;
      case '\r': escaped += "\\r"; break;
      case '\t': escaped += "\\t"; break;
      default:
        if (ch < 0x20) {
          constexpr char digits[] = "0123456789abcdef";
          escaped += "\\u00";
          escaped.push_back(digits[ch >> 4]);
          escaped.push_back(digits[ch & 0x0f]);
        } else {
          escaped.push_back(static_cast<char>(ch));
        }
    }
  }
  return escaped;
}

std::string hashHex(const qsafe::crypto::Hash& hash) {
  constexpr char digits[] = "0123456789abcdef";
  std::string output;
  output.reserve(hash.size() * 2);
  for (const auto byte : hash) {
    output.push_back(digits[byte >> 4]);
    output.push_back(digits[byte & 0x0f]);
  }
  return output;
}

void printError(const std::string& message) {
  std::cerr << "{\"ok\":false,\"error\":\"" << jsonEscape(message) << "\"}\n";
}

int usage() {
  std::cerr << "Usage:\n"
            << "  qsafe_vault ingest INPUT_FILE WORKSPACE\n"
            << "  qsafe_vault inspect WORKSPACE\n"
            << "  qsafe_vault audit WORKSPACE [SAMPLE_COUNT]\n"
            << "  qsafe_vault lose WORKSPACE SHARD_INDEX\n"
            << "  qsafe_vault recover WORKSPACE SHARD_INDEX OUTPUT_FILE\n"
            << "  qsafe_vault restore WORKSPACE OUTPUT_FILE\n";
  return 2;
}

int inspect(const std::filesystem::path& workspace) {
  std::string error;
  const auto info = qsafe::vault::inspectWorkspace(workspace, error);
  if (!info) {
    printError(error);
    return 1;
  }
  std::string storage_error;
  auto cloud = qsafe::storage::CloudStorage::open(workspace / "cloud", storage_error);
  if (!cloud) {
    printError(storage_error);
    return 1;
  }
  uint64_t available = 0;
  uint64_t unavailable = 0;
  for (uint64_t index = 0; index < info->signed_manifest.shard_count; ++index) {
    const auto shard = cloud->getShard(info->file_id, info->version, index);
    if (shard.status == qsafe::storage::ReadStatus::Available) ++available;
    else ++unavailable;
  }
  std::cout << "{\"ok\":true,\"file_id\":\"" << jsonEscape(info->file_id)
            << "\",\"version\":" << info->version
            << ",\"original_bytes\":" << info->original_length
            << ",\"source_shards\":" << info->source_shard_count
            << ",\"total_shards\":" << info->signed_manifest.shard_count
            << ",\"shard_size\":" << info->shard_size
            << ",\"available_shards\":" << available
            << ",\"unavailable_shards\":" << unavailable
            << ",\"root\":\"" << hashHex(info->signed_manifest.root) << "\"}\n";
  return 0;
}

int runAudit(const std::filesystem::path& workspace, uint64_t sample_count) {
  std::string error;
  const auto result = qsafe::vault::auditFile(workspace, sample_count, error);
  if (!result) {
    printError(error);
    return 1;
  }
  uint64_t verified = 0;
  uint64_t corrupt = 0;
  uint64_t unavailable = 0;
  uint64_t inconclusive = 0;
  std::vector<std::pair<uint64_t, const char*>> issues;
  for (const auto& shard : result->shards) {
    switch (shard.result) {
      case qsafe::audit::ShardResultCode::Verified: ++verified; break;
      case qsafe::audit::ShardResultCode::Corrupt:
        ++corrupt; issues.emplace_back(shard.index, "corrupt"); break;
      case qsafe::audit::ShardResultCode::Unavailable:
        ++unavailable; issues.emplace_back(shard.index, "unavailable"); break;
      case qsafe::audit::ShardResultCode::Inconclusive:
        ++inconclusive; issues.emplace_back(shard.index, "inconclusive"); break;
    }
  }
  std::cout << "{\"ok\":true,\"manifest_valid\":" << (result->manifest_valid ? "true" : "false")
            << ",\"checkpoint_valid\":" << (result->checkpoint_valid ? "true" : "false")
            << ",\"challenge_valid\":" << (result->challenge_valid ? "true" : "false")
            << ",\"sampled\":" << result->shards.size()
            << ",\"verified\":" << verified << ",\"corrupt\":" << corrupt
            << ",\"unavailable\":" << unavailable << ",\"inconclusive\":" << inconclusive
            << ",\"all_verified\":" << (result->allVerified() ? "true" : "false")
            << ",\"issues\":[";
  for (size_t i = 0; i < issues.size(); ++i) {
    if (i != 0) std::cout << ',';
    std::cout << "{\"index\":" << issues[i].first << ",\"result\":\""
              << issues[i].second << "\"}";
  }
  std::cout << "]}\n";
  return result->manifest_valid && result->checkpoint_valid && result->challenge_valid ? 0 : 1;
}

}

int main(int argc, char** argv) {
  if (argc < 2) return usage();
  const std::string command(argv[1]);
  if (command == "ingest") {
    if (argc != 4) return usage();
    std::string error;
    const auto info = qsafe::vault::ingestFile(argv[2], argv[3], error);
    if (!info) {
      printError(error);
      return 1;
    }
    std::cout << "{\"ok\":true,\"file_id\":\"" << jsonEscape(info->file_id)
              << "\",\"version\":" << info->version
              << ",\"original_bytes\":" << info->original_length
              << ",\"source_shards\":" << info->source_shard_count
              << ",\"total_shards\":" << info->signed_manifest.shard_count
              << ",\"shard_size\":" << info->shard_size
              << ",\"root\":\"" << hashHex(info->signed_manifest.root) << "\"}\n";
    return 0;
  }
  if (command == "inspect") {
    if (argc != 3) return usage();
    return inspect(argv[2]);
  }
  if (command == "audit") {
    if (argc != 3 && argc != 4) return usage();
    uint64_t count = 0;
    if (argc == 4 && !parseUnsigned(argv[3], count)) {
      printError("sample count must be an unsigned integer");
      return 2;
    }
    if (argc == 3) {
      std::string error;
      const auto info = qsafe::vault::inspectWorkspace(argv[2], error);
      if (!info) {
        printError(error);
        return 1;
      }
      count = std::max<uint64_t>(1, (info->signed_manifest.shard_count + 19) / 20);
    }
    return runAudit(argv[2], count);
  }
  if (command == "lose") {
    if (argc != 4) return usage();
    uint64_t index = 0;
    if (!parseUnsigned(argv[3], index)) {
      printError("shard index must be an unsigned integer");
      return 2;
    }
    std::string error;
    if (!qsafe::vault::markShardUnavailable(argv[2], index, error)) {
      printError(error);
      return 1;
    }
    std::cout << "{\"ok\":true,\"unavailable_shard\":" << index << "}\n";
    return 0;
  }
  if (command == "recover") {
    if (argc != 5) return usage();
    uint64_t index = 0;
    if (!parseUnsigned(argv[3], index)) {
      printError("shard index must be an unsigned integer");
      return 2;
    }
    const auto repair = qsafe::vault::recoverShard(argv[2], index);
    if (!repair.repaired()) {
      printError(repair.error);
      return 1;
    }
    std::string error;
    if (!qsafe::vault::restoreFile(argv[2], argv[4], error)) {
      printError(error);
      return 1;
    }
    std::cout << "{\"ok\":true,\"repaired_shard\":" << index
              << ",\"repair_bytes\":" << repair.repair_bytes
              << ",\"bytes_read\":" << repair.bytes_read
              << ",\"restored_file\":\"" << jsonEscape(argv[4]) << "\"}\n";
    return 0;
  }
  if (command == "restore") {
    if (argc != 4) return usage();
    std::string error;
    if (!qsafe::vault::restoreFile(argv[2], argv[3], error)) {
      printError(error);
      return 1;
    }
    std::error_code ec;
    const auto bytes = std::filesystem::file_size(argv[3], ec);
    if (ec) {
      printError("could not inspect restored file size");
      return 1;
    }
    std::cout << "{\"ok\":true,\"restored_bytes\":" << bytes << "}\n";
    return 0;
  }
  return usage();
}
