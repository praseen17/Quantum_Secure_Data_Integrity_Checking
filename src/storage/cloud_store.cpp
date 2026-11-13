#include "qsafe/storage/cloud_store.hpp"

#include "qsafe/crypto/hash.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <memory>
#include <utility>

namespace qsafe::storage {

namespace {

constexpr size_t kMaximumFileIdSize = 1024;
constexpr size_t kMaximumShardSize = 64 * 1024 * 1024;
constexpr size_t kMaximumPathSize = 64;

using Statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

std::string hex(const crypto::Hash& digest) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string output;
  output.reserve(digest.size() * 2);
  for (const uint8_t value : digest) {
    output.push_back(digits[value >> 4]);
    output.push_back(digits[value & 0x0f]);
  }
  return output;
}

std::optional<std::string> fileKey(const std::string& file_id) {
  if (file_id.empty() || file_id.size() > kMaximumFileIdSize ||
      !common::isValidUtf8(file_id)) {
    return std::nullopt;
  }
  common::Bytes bytes(file_id.begin(), file_id.end());
  const auto digest = crypto::sha256(bytes);
  if (!digest.has_value()) return std::nullopt;
  return hex(*digest);
}

bool bindKey(sqlite3_stmt* statement, const std::string& file_id, uint64_t version,
             uint64_t index) {
  return version <= static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max()) &&
         index <= static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max()) &&
         sqlite3_bind_text(statement, 1, file_id.c_str(), static_cast<int>(file_id.size()),
                           SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 2, static_cast<sqlite3_int64>(version)) == SQLITE_OK &&
         sqlite3_bind_int64(statement, 3, static_cast<sqlite3_int64>(index)) == SQLITE_OK;
}

bool writeBytes(const std::filesystem::path& path, const common::Bytes& bytes) {
  std::error_code filesystem_error;
  std::filesystem::create_directories(path.parent_path(), filesystem_error);
  if (filesystem_error) return false;
  auto temporary = path;
  temporary += ".tmp";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    if (!bytes.empty()) {
      output.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    output.close();
    if (!output) {
      std::filesystem::remove(temporary, filesystem_error);
      return false;
    }
  }
  std::filesystem::rename(temporary, path, filesystem_error);
  if (filesystem_error) {
    std::filesystem::remove(temporary, filesystem_error);
    return false;
  }
  return true;
}

std::optional<common::Bytes> readBytes(const std::filesystem::path& path, size_t max_size) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) return std::nullopt;
  const auto length = input.tellg();
  if (length < 0 || static_cast<uint64_t>(length) > max_size) return std::nullopt;
  common::Bytes bytes(static_cast<size_t>(length));
  input.seekg(0);
  if (!bytes.empty()) {
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
  if (!input) return std::nullopt;
  return bytes;
}

bool execute(sqlite3* database, const char* sql, std::string& error) {
  char* message = nullptr;
  if (sqlite3_exec(database, sql, nullptr, nullptr, &message) == SQLITE_OK) return true;
  error = message == nullptr ? sqlite3_errmsg(database) : message;
  sqlite3_free(message);
  return false;
}

}

CloudStorage::CloudStorage(std::filesystem::path root, sqlite3* database)
    : root_(std::move(root)), database_(database) {}

std::optional<CloudStorage> CloudStorage::open(const std::filesystem::path& root,
                                                std::string& error) {
  if (root.empty()) {
    error = "storage root is empty";
    return std::nullopt;
  }
  std::error_code filesystem_error;
  std::filesystem::create_directories(root, filesystem_error);
  if (filesystem_error) {
    error = filesystem_error.message();
    return std::nullopt;
  }
  sqlite3* database = nullptr;
  const auto database_path = root / "metadata.sqlite";
  if (sqlite3_open(database_path.c_str(), &database) != SQLITE_OK) {
    error = database == nullptr ? "sqlite open failed" : sqlite3_errmsg(database);
    if (database != nullptr) sqlite3_close(database);
    return std::nullopt;
  }
  if (!execute(database,
               "CREATE TABLE IF NOT EXISTS versions (file_id TEXT NOT NULL, version INTEGER NOT NULL, "
               "shard_count INTEGER NOT NULL, PRIMARY KEY(file_id, version));"
               "CREATE TABLE IF NOT EXISTS shards (file_id TEXT NOT NULL, version INTEGER NOT NULL, "
               "shard_index INTEGER NOT NULL, available INTEGER NOT NULL, "
               "PRIMARY KEY(file_id, version, shard_index));",
               error)) {
    sqlite3_close(database);
    return std::nullopt;
  }
  error.clear();
  return CloudStorage(root, database);
}

CloudStorage::~CloudStorage() {
  if (database_ != nullptr) sqlite3_close(database_);
}

CloudStorage::CloudStorage(CloudStorage&& other) noexcept
    : root_(std::move(other.root_)), database_(std::exchange(other.database_, nullptr)) {}

CloudStorage& CloudStorage::operator=(CloudStorage&& other) noexcept {
  if (this == &other) return *this;
  if (database_ != nullptr) sqlite3_close(database_);
  root_ = std::move(other.root_);
  database_ = std::exchange(other.database_, nullptr);
  return *this;
}

bool CloudStorage::put(const std::string& file_id, uint64_t version,
                       const std::vector<common::Bytes>& shards,
                       const std::vector<std::vector<crypto::Hash>>& paths, std::string& error) {
  const auto key = fileKey(file_id);
  if (!key.has_value() || version == 0 ||
      version > static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max()) ||
      shards.empty() || shards.size() != paths.size() ||
      shards.size() > static_cast<size_t>(std::numeric_limits<sqlite3_int64>::max())) {
    error = "invalid storage input";
    return false;
  }
  for (size_t i = 0; i < shards.size(); ++i) {
    if (shards[i].size() > kMaximumShardSize || paths[i].size() > kMaximumPathSize) {
      error = "shard or proof exceeds configured limit";
      return false;
    }
  }
  if (!execute(database_, "BEGIN IMMEDIATE", error)) return false;
  bool committed = false;
  auto rollback = [&]() {
    if (!committed) {
      std::string ignored;
      execute(database_, "ROLLBACK", ignored);
    }
  };

  sqlite3_stmt* raw_version = nullptr;
  if (sqlite3_prepare_v2(database_,
                        "INSERT INTO versions(file_id,version,shard_count) VALUES(?1,?2,?3)",
                        -1, &raw_version, nullptr) != SQLITE_OK) {
    error = sqlite3_errmsg(database_);
    rollback();
    return false;
  }
  Statement version_statement(raw_version, sqlite3_finalize);
  if (!bindKey(version_statement.get(), file_id, version, 0) ||
      sqlite3_bind_int64(version_statement.get(), 3, static_cast<sqlite3_int64>(shards.size())) !=
          SQLITE_OK ||
      sqlite3_step(version_statement.get()) != SQLITE_DONE) {
    error = sqlite3_errmsg(database_);
    rollback();
    return false;
  }

  for (size_t i = 0; i < shards.size(); ++i) {
    if (!writeBytes(shardPath(file_id, version, i), shards[i])) {
      error = "failed writing shard file";
      rollback();
      return false;
    }
    common::CanonicalWriter proof_writer;
    if (!proof_writer.writeU32(static_cast<uint32_t>(paths[i].size()))) {
      error = "failed encoding proof";
      rollback();
      return false;
    }
    for (const auto& hash : paths[i]) {
      if (!proof_writer.writeBytes(hash.data(), hash.size())) {
        error = "failed encoding proof";
        rollback();
        return false;
      }
    }
    if (!writeBytes(proofPath(file_id, version, i), proof_writer.data())) {
      error = "failed writing proof file";
      rollback();
      return false;
    }

    sqlite3_stmt* raw_shard = nullptr;
    if (sqlite3_prepare_v2(database_,
                          "INSERT INTO shards(file_id,version,shard_index,available) "
                          "VALUES(?1,?2,?3,1)",
                          -1, &raw_shard, nullptr) != SQLITE_OK) {
      error = sqlite3_errmsg(database_);
      rollback();
      return false;
    }
    Statement shard_statement(raw_shard, sqlite3_finalize);
    if (!bindKey(shard_statement.get(), file_id, version, i) ||
        sqlite3_step(shard_statement.get()) != SQLITE_DONE) {
      error = sqlite3_errmsg(database_);
      rollback();
      return false;
    }
  }

  if (!execute(database_, "COMMIT", error)) {
    rollback();
    return false;
  }
  committed = true;
  error.clear();
  return true;
}

ShardRead CloudStorage::getShard(const std::string& file_id, uint64_t version,
                                 uint64_t index) const {
  const auto available = isAvailable(file_id, version, index);
  if (!available.has_value()) return {ReadStatus::Unavailable, {}};
  if (!*available) return {ReadStatus::Unavailable, {}};
  const auto bytes = readBytes(shardPath(file_id, version, index), kMaximumShardSize);
  if (!bytes.has_value()) return {ReadStatus::Error, {}};
  return {ReadStatus::Available, *bytes};
}

std::optional<std::vector<crypto::Hash>> CloudStorage::getPath(const std::string& file_id,
                                                               uint64_t version,
                                                               uint64_t index) const {
  const auto available = isAvailable(file_id, version, index);
  if (!available.has_value()) return std::nullopt;
  const auto encoded = readBytes(proofPath(file_id, version, index), 4 + kMaximumPathSize * 36);
  if (!encoded.has_value()) return std::nullopt;
  common::CanonicalReader reader(*encoded);
  uint32_t count = 0;
  if (!reader.readU32(count) || count > kMaximumPathSize) return std::nullopt;
  std::vector<crypto::Hash> hashes;
  hashes.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    common::Bytes bytes;
    if (!reader.readBytes(bytes, crypto::Hash{}.size()) || bytes.size() != crypto::Hash{}.size()) {
      return std::nullopt;
    }
    crypto::Hash hash{};
    std::copy(bytes.begin(), bytes.end(), hash.begin());
    hashes.push_back(hash);
  }
  if (!reader.finished()) return std::nullopt;
  return hashes;
}

bool CloudStorage::setAvailability(const std::string& file_id, uint64_t version, uint64_t index,
                                   ShardAvailability availability, std::string& error) {
  sqlite3_stmt* raw = nullptr;
  if (sqlite3_prepare_v2(database_,
                        "UPDATE shards SET available=?1 WHERE file_id=?2 AND version=?3 AND "
                        "shard_index=?4",
                        -1, &raw, nullptr) != SQLITE_OK) {
    error = sqlite3_errmsg(database_);
    return false;
  }
  Statement statement(raw, sqlite3_finalize);
  if (sqlite3_bind_int(statement.get(), 1,
                       availability == ShardAvailability::Available ? 1 : 0) != SQLITE_OK ||
      version > static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max()) ||
      index > static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max()) ||
      sqlite3_bind_text(statement.get(), 2, file_id.c_str(), static_cast<int>(file_id.size()),
                        SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_int64(statement.get(), 3, static_cast<sqlite3_int64>(version)) != SQLITE_OK ||
      sqlite3_bind_int64(statement.get(), 4, static_cast<sqlite3_int64>(index)) != SQLITE_OK ||
      sqlite3_step(statement.get()) != SQLITE_DONE || sqlite3_changes(database_) != 1) {
    error = sqlite3_errmsg(database_);
    return false;
  }
  error.clear();
  return true;
}

bool CloudStorage::injectFaultShardBytes(const std::string& file_id, uint64_t version,
                                         uint64_t index, const common::Bytes& bytes,
                                         std::string& error) {
  const auto key = fileKey(file_id);
  const auto available = isAvailable(file_id, version, index);
  if (!key.has_value() || !available.has_value() || !*available ||
      bytes.size() > kMaximumShardSize) {
    error = "invalid fault injection request";
    return false;
  }
  if (!writeBytes(shardPath(file_id, version, index), bytes)) {
    error = "failed writing injected shard";
    return false;
  }
  error.clear();
  return true;
}

bool CloudStorage::injectFaultProofBytes(const std::string& file_id, uint64_t version,
                                         uint64_t index, const common::Bytes& bytes,
                                         std::string& error) {
  const auto key = fileKey(file_id);
  const auto available = isAvailable(file_id, version, index);
  if (!key.has_value() || !available.has_value() || bytes.size() > 4 + kMaximumPathSize * 36) {
    error = "invalid proof fault injection request";
    return false;
  }
  if (!writeBytes(proofPath(file_id, version, index), bytes)) {
    error = "failed writing injected proof";
    return false;
  }
  error.clear();
  return true;
}

bool CloudStorage::storeRepairedShard(const std::string& file_id, uint64_t version,
                                      uint64_t index, const common::Bytes& bytes,
                                      std::string& error) {
  const auto key = fileKey(file_id);
  const auto available = isAvailable(file_id, version, index);
  if (!key.has_value() || !available.has_value() || bytes.size() > kMaximumShardSize ||
      version > static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max()) ||
      index > static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max())) {
    error = "invalid repaired shard request";
    return false;
  }
  if (!writeBytes(shardPath(file_id, version, index), bytes)) {
    error = "failed writing repaired shard";
    return false;
  }
  sqlite3_stmt* raw = nullptr;
  if (sqlite3_prepare_v2(database_,
                        "UPDATE shards SET available=1 WHERE file_id=?1 AND version=?2 AND "
                        "shard_index=?3",
                        -1, &raw, nullptr) != SQLITE_OK) {
    error = sqlite3_errmsg(database_);
    return false;
  }
  Statement statement(raw, sqlite3_finalize);
  if (!bindKey(statement.get(), file_id, version, index) ||
      sqlite3_step(statement.get()) != SQLITE_DONE || sqlite3_changes(database_) != 1) {
    error = sqlite3_errmsg(database_);
    return false;
  }
  error.clear();
  return true;
}

std::optional<bool> CloudStorage::isAvailable(const std::string& file_id, uint64_t version,
                                               uint64_t index) const {
  sqlite3_stmt* raw = nullptr;
  if (sqlite3_prepare_v2(database_,
                        "SELECT available FROM shards WHERE file_id=?1 AND version=?2 AND "
                        "shard_index=?3",
                        -1, &raw, nullptr) != SQLITE_OK) {
    return std::nullopt;
  }
  Statement statement(raw, sqlite3_finalize);
  if (!bindKey(statement.get(), file_id, version, index)) return std::nullopt;
  const int status = sqlite3_step(statement.get());
  if (status == SQLITE_DONE) return std::nullopt;
  if (status != SQLITE_ROW) return std::nullopt;
  return sqlite3_column_int(statement.get(), 0) != 0;
}

std::filesystem::path CloudStorage::shardPath(const std::string& file_id, uint64_t version,
                                               uint64_t index) const {
  const auto key = fileKey(file_id);
  return root_ / key.value_or("invalid") / ("v" + std::to_string(version)) /
         ("shard-" + std::to_string(index) + ".bin");
}

std::filesystem::path CloudStorage::proofPath(const std::string& file_id, uint64_t version,
                                               uint64_t index) const {
  const auto key = fileKey(file_id);
  return root_ / key.value_or("invalid") / ("v" + std::to_string(version)) /
         ("proof-" + std::to_string(index) + ".bin");
}

}
