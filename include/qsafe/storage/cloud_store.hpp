#pragma once

#include "qsafe/common/encoding.hpp"
#include "qsafe/crypto/hash.hpp"

#include <sqlite3.h>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace qsafe::storage {

enum class ReadStatus { Available, Unavailable, Error };
enum class ShardAvailability { Available, Unavailable };

struct ShardRead {
  ReadStatus status = ReadStatus::Unavailable;
  common::Bytes bytes;
};

class CloudStorage {
 public:
  static std::optional<CloudStorage> open(const std::filesystem::path& root, std::string& error);
  ~CloudStorage();
  CloudStorage(const CloudStorage&) = delete;
  CloudStorage& operator=(const CloudStorage&) = delete;
  CloudStorage(CloudStorage&& other) noexcept;
  CloudStorage& operator=(CloudStorage&& other) noexcept;

  bool put(const std::string& file_id, uint64_t version,
           const std::vector<common::Bytes>& shards,
           const std::vector<std::vector<crypto::Hash>>& paths, std::string& error);
  ShardRead getShard(const std::string& file_id, uint64_t version, uint64_t index) const;
  std::optional<std::vector<crypto::Hash>> getPath(const std::string& file_id, uint64_t version,
                                                   uint64_t index) const;
  bool setAvailability(const std::string& file_id, uint64_t version, uint64_t index,
                       ShardAvailability availability, std::string& error);
  bool injectFaultShardBytes(const std::string& file_id, uint64_t version, uint64_t index,
                             const common::Bytes& bytes, std::string& error);
  bool injectFaultProofBytes(const std::string& file_id, uint64_t version, uint64_t index,
                             const common::Bytes& bytes, std::string& error);
  bool storeRepairedShard(const std::string& file_id, uint64_t version, uint64_t index,
                          const common::Bytes& bytes, std::string& error);

 private:
  CloudStorage(std::filesystem::path root, sqlite3* database);
  std::filesystem::path shardPath(const std::string& file_id, uint64_t version,
                                  uint64_t index) const;
  std::filesystem::path proofPath(const std::string& file_id, uint64_t version,
                                  uint64_t index) const;
  std::optional<bool> isAvailable(const std::string& file_id, uint64_t version,
                                  uint64_t index) const;

  std::filesystem::path root_;
  sqlite3* database_ = nullptr;
};

}
