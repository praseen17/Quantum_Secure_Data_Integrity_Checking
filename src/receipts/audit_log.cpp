#include "qsafe/receipts/audit_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

namespace qsafe::receipts {

namespace {

constexpr uint32_t kCheckpointFormat = 1;
constexpr size_t kMaximumReceiptSize = 4096;
constexpr size_t kMaximumSignatureSize = 8192;
constexpr size_t kMaximumFileIdSize = 1024;
constexpr size_t kNonceSize = 32;

using Statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

bool valid(const Receipt& receipt) {
  return !receipt.file_id.empty() && receipt.file_id.size() <= kMaximumFileIdSize &&
         common::isValidUtf8(receipt.file_id) && receipt.version > 0 &&
         receipt.nonce.size() == kNonceSize &&
         static_cast<uint8_t>(receipt.result) <=
             static_cast<uint8_t>(VerificationOutcome::Inconclusive) &&
         static_cast<uint8_t>(receipt.repair) <= static_cast<uint8_t>(RepairOutcome::Failed);
}

bool execute(sqlite3* database, const char* sql, std::string& error) {
  char* message = nullptr;
  if (sqlite3_exec(database, sql, nullptr, nullptr, &message) == SQLITE_OK) return true;
  error = message == nullptr ? sqlite3_errmsg(database) : message;
  sqlite3_free(message);
  return false;
}

std::optional<common::Bytes> blob(sqlite3_stmt* statement, int column, size_t maximum) {
  const int size = sqlite3_column_bytes(statement, column);
  const auto* data = static_cast<const uint8_t*>(sqlite3_column_blob(statement, column));
  if (size < 0 || static_cast<size_t>(size) > maximum || (size != 0 && data == nullptr)) {
    return std::nullopt;
  }
  if (size == 0) return common::Bytes{};
  return common::Bytes(data, data + size);
}

std::optional<crypto::Hash> chainHash(const crypto::Hash& previous,
                                      const common::Bytes& receipt_bytes) {
  const auto receipt_digest = crypto::sha256(receipt_bytes);
  if (!receipt_digest.has_value()) return std::nullopt;
  common::CanonicalWriter writer;
  if (!writer.writeString("LOG") || !writer.writeBytes(previous.data(), previous.size()) ||
      !writer.writeBytes(receipt_digest->data(), receipt_digest->size())) {
    return std::nullopt;
  }
  return crypto::sha256(writer.data());
}

std::optional<common::Bytes> encodeCheckpoint(const LogCheckpoint& checkpoint) {
  common::CanonicalWriter writer;
  if (!writer.writeU32(kCheckpointFormat) || !writer.writeU64(checkpoint.sequence) ||
      !writer.writeString(checkpoint.file_id) || !writer.writeU64(checkpoint.version) ||
      !writer.writeBytes(checkpoint.head.data(), checkpoint.head.size())) {
    return std::nullopt;
  }
  return writer.data();
}

std::optional<LogCheckpoint> decodeCheckpoint(const common::Bytes& encoded) {
  common::CanonicalReader reader(encoded);
  LogCheckpoint checkpoint;
  uint32_t format = 0;
  common::Bytes head;
  if (!reader.readU32(format) || format != kCheckpointFormat ||
      !reader.readU64(checkpoint.sequence) || !reader.readString(checkpoint.file_id,
                                                                  kMaximumFileIdSize) ||
      !reader.readU64(checkpoint.version) || !reader.readBytes(head, crypto::Hash{}.size()) ||
      head.size() != crypto::Hash{}.size() || !reader.finished()) {
    return std::nullopt;
  }
  std::copy(head.begin(), head.end(), checkpoint.head.begin());
  if ((checkpoint.sequence == 0 && (!checkpoint.file_id.empty() || checkpoint.version != 0)) ||
      (checkpoint.sequence != 0 && (checkpoint.file_id.empty() || checkpoint.version == 0))) {
    return std::nullopt;
  }
  return checkpoint;
}

bool writeCheckpoint(const std::filesystem::path& path, const LogCheckpoint& checkpoint,
                     std::string& error) {
  const auto encoded = encodeCheckpoint(checkpoint);
  if (!encoded.has_value()) {
    error = "checkpoint encoding failed";
    return false;
  }
  const auto parent = path.parent_path();
  std::error_code filesystem_error;
  if (!parent.empty()) std::filesystem::create_directories(parent, filesystem_error);
  if (filesystem_error) {
    error = filesystem_error.message();
    return false;
  }
  static std::atomic<uint64_t> temporary_id{0};
  auto temporary = path;
  temporary += ".tmp." + std::to_string(temporary_id.fetch_add(1));
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) {
      error = "checkpoint temporary file could not be opened";
      return false;
    }
    output.write(reinterpret_cast<const char*>(encoded->data()),
                 static_cast<std::streamsize>(encoded->size()));
    output.close();
    if (!output) {
      std::filesystem::remove(temporary, filesystem_error);
      error = "checkpoint write failed";
      return false;
    }
  }
  std::filesystem::rename(temporary, path, filesystem_error);
  if (filesystem_error) {
    std::filesystem::remove(temporary, filesystem_error);
    error = "checkpoint replacement failed";
    return false;
  }
  return true;
}

std::optional<LogCheckpoint> readCheckpoint(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) return std::nullopt;
  const auto end = input.tellg();
  if (end < 0 || end > 2048) return std::nullopt;
  common::Bytes encoded(static_cast<size_t>(end));
  input.seekg(0);
  if (!encoded.empty()) {
    input.read(reinterpret_cast<char*>(encoded.data()), static_cast<std::streamsize>(encoded.size()));
  }
  if (!input) return std::nullopt;
  return decodeCheckpoint(encoded);
}

bool bindBlob(sqlite3_stmt* statement, int index, const common::Bytes& value) {
  return sqlite3_bind_blob(statement, index, value.data(), static_cast<int>(value.size()),
                           SQLITE_TRANSIENT) == SQLITE_OK;
}

}

bool Receipt::operator==(const Receipt& other) const {
  return file_id == other.file_id && version == other.version && challenge_id == other.challenge_id &&
         nonce == other.nonce && shard_index == other.shard_index &&
         stripe_index == other.stripe_index && result == other.result &&
         original_root == other.original_root && repair == other.repair &&
         evidence_digest == other.evidence_digest;
}

std::optional<common::Bytes> serialize(const Receipt& receipt) {
  if (!valid(receipt)) return std::nullopt;
  common::CanonicalWriter writer;
  if (!writer.writeString(receipt.file_id) || !writer.writeU64(receipt.version) ||
      !writer.writeBytes(receipt.challenge_id.data(), receipt.challenge_id.size()) ||
      !writer.writeBytes(receipt.nonce) || !writer.writeU64(receipt.shard_index) ||
      !writer.writeU64(receipt.stripe_index) ||
      !writer.writeU8(static_cast<uint8_t>(receipt.result)) ||
      !writer.writeBytes(receipt.original_root.data(), receipt.original_root.size()) ||
      !writer.writeU8(static_cast<uint8_t>(receipt.repair)) ||
      !writer.writeBytes(receipt.evidence_digest.data(), receipt.evidence_digest.size())) {
    return std::nullopt;
  }
  return writer.data();
}

std::optional<Receipt> deserialize(const common::Bytes& encoded) {
  if (encoded.size() > kMaximumReceiptSize) return std::nullopt;
  common::CanonicalReader reader(encoded);
  Receipt receipt;
  common::Bytes challenge_id;
  common::Bytes root;
  common::Bytes evidence_digest;
  uint8_t result = 0;
  uint8_t repair = 0;
  if (!reader.readString(receipt.file_id, kMaximumFileIdSize) ||
      !reader.readU64(receipt.version) ||
      !reader.readBytes(challenge_id, crypto::Hash{}.size()) ||
      challenge_id.size() != crypto::Hash{}.size() || !reader.readBytes(receipt.nonce, kNonceSize) ||
      !reader.readU64(receipt.shard_index) || !reader.readU64(receipt.stripe_index) ||
      !reader.readU8(result) || !reader.readBytes(root, crypto::Hash{}.size()) ||
      root.size() != crypto::Hash{}.size() || !reader.readU8(repair) ||
      !reader.readBytes(evidence_digest, crypto::Hash{}.size()) ||
      evidence_digest.size() != crypto::Hash{}.size() || !reader.finished()) {
    return std::nullopt;
  }
  receipt.result = static_cast<VerificationOutcome>(result);
  receipt.repair = static_cast<RepairOutcome>(repair);
  std::copy(challenge_id.begin(), challenge_id.end(), receipt.challenge_id.begin());
  std::copy(root.begin(), root.end(), receipt.original_root.begin());
  std::copy(evidence_digest.begin(), evidence_digest.end(), receipt.evidence_digest.begin());
  if (!valid(receipt)) return std::nullopt;
  return receipt;
}

std::optional<common::Bytes> sign(const Receipt& receipt, const crypto::LiboqsSigner& signer,
                                  const crypto::SigningKeyPair& auditor_key_pair) {
  const auto encoded = serialize(receipt);
  if (!encoded.has_value()) return std::nullopt;
  return signer.sign(*encoded, auditor_key_pair);
}

bool verify(const Receipt& receipt, const common::Bytes& signature,
            const crypto::LiboqsSigner& signer,
            const common::Bytes& trusted_auditor_public_key) {
  const auto encoded = serialize(receipt);
  return encoded.has_value() && signer.verify(*encoded, signature, trusted_auditor_public_key);
}

AuditLog::AuditLog(std::filesystem::path database_path, sqlite3* database)
    : database_path_(std::move(database_path)), database_(database) {}

std::optional<AuditLog> AuditLog::open(const std::filesystem::path& database_path,
                                       std::string& error) {
  if (database_path.empty()) {
    error = "audit database path is empty";
    return std::nullopt;
  }
  const auto parent = database_path.parent_path();
  std::error_code filesystem_error;
  if (!parent.empty()) std::filesystem::create_directories(parent, filesystem_error);
  if (filesystem_error) {
    error = filesystem_error.message();
    return std::nullopt;
  }
  sqlite3* database = nullptr;
  if (sqlite3_open(database_path.c_str(), &database) != SQLITE_OK) {
    error = database == nullptr ? "audit database open failed" : sqlite3_errmsg(database);
    if (database != nullptr) sqlite3_close(database);
    return std::nullopt;
  }
  if (!execute(database,
               "CREATE TABLE IF NOT EXISTS entries (sequence INTEGER PRIMARY KEY, "
               "payload BLOB NOT NULL, signature BLOB NOT NULL, previous BLOB NOT NULL, "
               "head BLOB NOT NULL)",
               error)) {
    sqlite3_close(database);
    return std::nullopt;
  }
  error.clear();
  return AuditLog(database_path, database);
}

AuditLog::~AuditLog() {
  if (database_ != nullptr) sqlite3_close(database_);
}

AuditLog::AuditLog(AuditLog&& other) noexcept
    : database_path_(std::move(other.database_path_)),
      database_(std::exchange(other.database_, nullptr)) {}

AuditLog& AuditLog::operator=(AuditLog&& other) noexcept {
  if (this == &other) return *this;
  if (database_ != nullptr) sqlite3_close(database_);
  database_path_ = std::move(other.database_path_);
  database_ = std::exchange(other.database_, nullptr);
  return *this;
}

bool AuditLog::append(const Receipt& receipt, const crypto::LiboqsSigner& signer,
                      const crypto::SigningKeyPair& auditor_key_pair,
                      const std::filesystem::path& checkpoint_path, std::string& error) {
  const auto signature = sign(receipt, signer, auditor_key_pair);
  if (!signature.has_value()) {
    error = "receipt signature failed";
    return false;
  }
  return appendSigned(receipt, *signature, signer, auditor_key_pair.public_key,
                      checkpoint_path, error);
}

bool AuditLog::appendSigned(const Receipt& receipt, const common::Bytes& signature,
                            const crypto::LiboqsSigner& signer,
                            const common::Bytes& trusted_auditor_public_key,
                            const std::filesystem::path& checkpoint_path, std::string& error,
                            uint64_t* verification_nanoseconds) {
  const auto payload = serialize(receipt);
  const auto verification_start = std::chrono::steady_clock::now();
  const bool signature_valid = payload.has_value() && signature.size() <= kMaximumSignatureSize &&
      qsafe::receipts::verify(receipt, signature, signer, trusted_auditor_public_key);
  if (verification_nanoseconds != nullptr) {
    *verification_nanoseconds = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - verification_start).count());
  }
  if (!signature_valid) {
    error = "receipt encoding or signature is invalid";
    return false;
  }

  sqlite3_stmt* raw_latest = nullptr;
  if (sqlite3_prepare_v2(database_,
                        "SELECT sequence,payload,head FROM entries ORDER BY sequence DESC LIMIT 1",
                        -1, &raw_latest, nullptr) != SQLITE_OK) {
    error = sqlite3_errmsg(database_);
    return false;
  }
  Statement latest_statement(raw_latest, sqlite3_finalize);
  const int latest_status = sqlite3_step(latest_statement.get());
  uint64_t previous_sequence = 0;
  crypto::Hash previous_head{};
  if (latest_status == SQLITE_ROW) {
    previous_sequence = static_cast<uint64_t>(sqlite3_column_int64(latest_statement.get(), 0));
    const auto previous_payload = blob(latest_statement.get(), 1, kMaximumReceiptSize);
    const auto previous_hash = blob(latest_statement.get(), 2, crypto::Hash{}.size());
    if (!previous_payload.has_value() || !previous_hash.has_value() ||
        previous_hash->size() != previous_head.size()) {
      error = "latest audit entry is malformed";
      return false;
    }
    const auto previous_receipt = deserialize(*previous_payload);
    if (!previous_receipt.has_value()) {
      error = "audit log version rollback or malformed prior receipt";
      return false;
    }
    std::copy(previous_hash->begin(), previous_hash->end(), previous_head.begin());
  } else if (latest_status != SQLITE_DONE) {
    error = sqlite3_errmsg(database_);
    return false;
  }

  sqlite3_stmt* raw_history = nullptr;
  if (sqlite3_prepare_v2(database_, "SELECT payload FROM entries", -1, &raw_history, nullptr) !=
      SQLITE_OK) {
    error = sqlite3_errmsg(database_);
    return false;
  }
  Statement history(raw_history, sqlite3_finalize);
  while (true) {
    const int status = sqlite3_step(history.get());
    if (status == SQLITE_DONE) break;
    if (status != SQLITE_ROW) {
      error = sqlite3_errmsg(database_);
      return false;
    }
    const auto prior_payload = blob(history.get(), 0, kMaximumReceiptSize);
    const auto prior_receipt = prior_payload.has_value() ? deserialize(*prior_payload)
                                                          : std::nullopt;
    if (!prior_receipt.has_value()) {
      error = "audit log contains malformed prior receipt";
      return false;
    }
    if (prior_receipt->file_id == receipt.file_id && receipt.version < prior_receipt->version) {
      error = "audit log version rollback";
      return false;
    }
  }

  if (previous_sequence != 0) {
    if (!verify(checkpoint_path, signer, trusted_auditor_public_key, error)) return false;
  } else if (std::filesystem::exists(checkpoint_path)) {
    error = "checkpoint exists but audit log has no entries";
    return false;
  }
  if (previous_sequence >= static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max())) {
    error = "audit sequence limit reached";
    return false;
  }

  const auto head = chainHash(previous_head, *payload);
  if (!head.has_value()) {
    error = "audit chain hash failed";
    return false;
  }
  if (!execute(database_, "BEGIN IMMEDIATE", error)) return false;
  sqlite3_stmt* raw_insert = nullptr;
  if (sqlite3_prepare_v2(database_,
                        "INSERT INTO entries(sequence,payload,signature,previous,head) "
                        "VALUES(?1,?2,?3,?4,?5)",
                        -1, &raw_insert, nullptr) != SQLITE_OK) {
    error = sqlite3_errmsg(database_);
    std::string ignored;
    execute(database_, "ROLLBACK", ignored);
    return false;
  }
  Statement insert(raw_insert, sqlite3_finalize);
  common::Bytes previous_bytes(previous_head.begin(), previous_head.end());
  common::Bytes head_bytes(head->begin(), head->end());
  if (sqlite3_bind_int64(insert.get(), 1, static_cast<sqlite3_int64>(previous_sequence + 1)) !=
          SQLITE_OK ||
      !bindBlob(insert.get(), 2, *payload) || !bindBlob(insert.get(), 3, signature) ||
      !bindBlob(insert.get(), 4, previous_bytes) || !bindBlob(insert.get(), 5, head_bytes) ||
      sqlite3_step(insert.get()) != SQLITE_DONE) {
    error = sqlite3_errmsg(database_);
    std::string ignored;
    execute(database_, "ROLLBACK", ignored);
    return false;
  }
  if (!execute(database_, "COMMIT", error)) {
    std::string ignored;
    execute(database_, "ROLLBACK", ignored);
    return false;
  }

  const LogCheckpoint checkpoint{previous_sequence + 1, receipt.file_id, receipt.version, *head};
  if (!writeCheckpoint(checkpoint_path, checkpoint, error)) {
    error = "receipt committed but external checkpoint update failed: " + error;
    return false;
  }
  error.clear();
  return true;
}

bool AuditLog::verify(const std::filesystem::path& checkpoint_path,
                      const crypto::LiboqsSigner& signer,
                      const common::Bytes& trusted_auditor_public_key,
                      std::string& error) const {
  const auto checkpoint = readCheckpoint(checkpoint_path);
  if (!checkpoint.has_value()) {
    error = "external checkpoint is missing or malformed";
    return false;
  }

  sqlite3_stmt* raw = nullptr;
  if (sqlite3_prepare_v2(database_,
                        "SELECT sequence,payload,signature,previous,head FROM entries ORDER BY sequence",
                        -1, &raw, nullptr) != SQLITE_OK) {
    error = sqlite3_errmsg(database_);
    return false;
  }
  Statement statement(raw, sqlite3_finalize);
  uint64_t expected_sequence = 1;
  crypto::Hash expected_previous{};
  std::string final_file_id;
  uint64_t final_version = 0;
  while (true) {
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE) break;
    if (status != SQLITE_ROW) {
      error = sqlite3_errmsg(database_);
      return false;
    }
    const auto sequence_value = sqlite3_column_int64(statement.get(), 0);
    const auto payload = blob(statement.get(), 1, kMaximumReceiptSize);
    const auto signature = blob(statement.get(), 2, kMaximumSignatureSize);
    const auto previous = blob(statement.get(), 3, crypto::Hash{}.size());
    const auto head = blob(statement.get(), 4, crypto::Hash{}.size());
    if (sequence_value < 1 || static_cast<uint64_t>(sequence_value) != expected_sequence ||
        !payload.has_value() || !signature.has_value() || !previous.has_value() ||
        !head.has_value() || previous->size() != expected_previous.size() ||
        head->size() != expected_previous.size()) {
      error = "audit log sequence or field encoding is invalid";
      return false;
    }
    if (!std::equal(previous->begin(), previous->end(), expected_previous.begin())) {
      error = "audit log previous-head mismatch";
      return false;
    }
    const auto receipt = deserialize(*payload);
    if (!receipt.has_value() || !signer.verify(*payload, *signature, trusted_auditor_public_key)) {
      error = "audit receipt signature or encoding is invalid";
      return false;
    }
    const auto computed_head = chainHash(expected_previous, *payload);
    if (!computed_head.has_value() ||
        !std::equal(head->begin(), head->end(), computed_head->begin())) {
      error = "audit log chain head mismatch";
      return false;
    }
    expected_previous = *computed_head;
    final_file_id = receipt->file_id;
    final_version = receipt->version;
    ++expected_sequence;
  }

  const uint64_t final_sequence = expected_sequence - 1;
  if (checkpoint->sequence != final_sequence || checkpoint->head != expected_previous ||
      checkpoint->file_id != final_file_id || checkpoint->version != final_version) {
    error = "audit log does not match external checkpoint";
    return false;
  }
  error.clear();
  return true;
}

}
