#include "qsafe/vault/workspace.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    path_ = std::filesystem::temp_directory_path() /
        ("qsafe-vault-test-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(path_);
  }
  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }
  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

std::vector<uint8_t> readAll(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  EXPECT_TRUE(input.good());
  const auto size = input.tellg();
  EXPECT_GE(size, 0);
  std::vector<uint8_t> bytes(static_cast<size_t>(size));
  input.seekg(0);
  if (!bytes.empty()) {
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
  EXPECT_TRUE(input.good() || input.eof());
  return bytes;
}

}

TEST(VaultWorkspace, IngestsAuditsRepairsAndRestoresMultipleStripes) {
  TemporaryDirectory temporary;
  const auto input_path = temporary.path() / "user-data.bin";
  std::vector<uint8_t> expected(570 * 1024 + 719);
  for (size_t index = 0; index < expected.size(); ++index) {
    expected[index] = static_cast<uint8_t>((index * 37 + 19) & 0xff);
  }
  {
    std::ofstream output(input_path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(expected.data()),
                 static_cast<std::streamsize>(expected.size()));
  }

  std::string error;
  const auto workspace = temporary.path() / "workspace";
  const auto info = qsafe::vault::ingestFile(input_path, workspace, error);
  ASSERT_TRUE(info.has_value()) << error;
  EXPECT_EQ(info->original_length, expected.size());
  ASSERT_EQ(info->signed_manifest.shard_count, 18U);

  const auto audit = qsafe::vault::auditFile(workspace, info->signed_manifest.shard_count, error);
  ASSERT_TRUE(audit.has_value()) << error;
  EXPECT_TRUE(audit->manifest_valid);
  EXPECT_TRUE(audit->checkpoint_valid);
  EXPECT_TRUE(audit->challenge_valid);
  EXPECT_TRUE(audit->allVerified());

  ASSERT_TRUE(qsafe::vault::markShardUnavailable(workspace, 2, error)) << error;
  const auto damaged_audit = qsafe::vault::auditFile(workspace,
      info->signed_manifest.shard_count, error);
  ASSERT_TRUE(damaged_audit.has_value()) << error;
  EXPECT_FALSE(damaged_audit->allVerified());

  const auto repair = qsafe::vault::recoverShard(workspace, 2);
  ASSERT_TRUE(repair.repaired()) << repair.error;
  const auto restored_path = temporary.path() / "restored.bin";
  ASSERT_TRUE(qsafe::vault::restoreFile(workspace, restored_path, error)) << error;
  EXPECT_EQ(readAll(restored_path), expected);
}

TEST(VaultWorkspace, RejectsMalformedWorkspaceMetadata) {
  TemporaryDirectory temporary;
  const auto workspace = temporary.path() / "workspace";
  std::filesystem::create_directories(workspace);
  {
    std::ofstream output(workspace / "workspace.qsv", std::ios::binary);
    output << "not a Q-SAFE workspace";
  }
  std::string error;
  EXPECT_FALSE(qsafe::vault::inspectWorkspace(workspace, error).has_value());
  EXPECT_FALSE(error.empty());
}

TEST(VaultWorkspace, RejectsTamperedSignedWorkspaceMetadata) {
  TemporaryDirectory temporary;
  const auto input_path = temporary.path() / "signed.bin";
  {
    std::ofstream output(input_path, std::ios::binary);
    output << "workspace metadata must be signed";
  }
  const auto workspace = temporary.path() / "workspace";
  std::string error;
  ASSERT_TRUE(qsafe::vault::ingestFile(input_path, workspace, error).has_value()) << error;
  const auto metadata_path = workspace / "workspace.qsv";
  auto bytes = readAll(metadata_path);
  ASSERT_GT(bytes.size(), 8U);
  bytes[bytes.size() / 2] ^= 0x01;
  {
    std::ofstream output(metadata_path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  EXPECT_FALSE(qsafe::vault::inspectWorkspace(workspace, error).has_value());
  EXPECT_NE(error.find("signature"), std::string::npos);
}
