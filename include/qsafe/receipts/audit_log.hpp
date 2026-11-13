#pragma once

#include "qsafe/crypto/signature.hpp"
#include "qsafe/crypto/hash.hpp"

#include <sqlite3.h>

#include <filesystem>
#include <optional>
#include <string>

namespace qsafe::receipts {

enum class VerificationOutcome : uint8_t { Verified = 0, Corrupt = 1, Unavailable = 2, Inconclusive = 3 };
enum class RepairOutcome : uint8_t { NotAttempted = 0, Repaired = 1, Failed = 2 };

struct Receipt {
  std::string file_id;
  uint64_t version = 0;
  crypto::Hash challenge_id{};
  common::Bytes nonce;
  uint64_t shard_index = 0;
  uint64_t stripe_index = 0;
  VerificationOutcome result = VerificationOutcome::Inconclusive;
  crypto::Hash original_root{};
  RepairOutcome repair = RepairOutcome::NotAttempted;
  crypto::Hash evidence_digest{};

  bool operator==(const Receipt& other) const;
};

std::optional<common::Bytes> serialize(const Receipt& receipt);
std::optional<Receipt> deserialize(const common::Bytes& encoded);
std::optional<common::Bytes> sign(const Receipt& receipt, const crypto::LiboqsSigner& signer,
                                  const crypto::SigningKeyPair& auditor_key_pair);
bool verify(const Receipt& receipt, const common::Bytes& signature,
            const crypto::LiboqsSigner& signer,
            const common::Bytes& trusted_auditor_public_key);

struct LogCheckpoint {
  uint64_t sequence = 0;
  std::string file_id;
  uint64_t version = 0;
  crypto::Hash head{};
};

class AuditLog {
 public:
  static std::optional<AuditLog> open(const std::filesystem::path& database_path,
                                      std::string& error);
  ~AuditLog();
  AuditLog(const AuditLog&) = delete;
  AuditLog& operator=(const AuditLog&) = delete;
  AuditLog(AuditLog&& other) noexcept;
  AuditLog& operator=(AuditLog&& other) noexcept;

  bool append(const Receipt& receipt, const crypto::LiboqsSigner& signer,
              const crypto::SigningKeyPair& auditor_key_pair,
              const std::filesystem::path& checkpoint_path, std::string& error);
  bool appendSigned(const Receipt& receipt, const common::Bytes& signature,
                    const crypto::LiboqsSigner& signer,
                    const common::Bytes& trusted_auditor_public_key,
                    const std::filesystem::path& checkpoint_path, std::string& error,
                    uint64_t* verification_nanoseconds = nullptr);
  bool verify(const std::filesystem::path& checkpoint_path,
              const crypto::LiboqsSigner& signer,
              const common::Bytes& trusted_auditor_public_key, std::string& error) const;

 private:
  AuditLog(std::filesystem::path database_path, sqlite3* database);
  std::filesystem::path database_path_;
  sqlite3* database_ = nullptr;
};

}
