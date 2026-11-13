#include "qsafe/receipts/audit_log.hpp"
#include "qsafe/audit/risk_sampling.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace qsafe::receipts {

namespace {

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    path_ = std::filesystem::temp_directory_path() /
            ("qsafe-receipt-test-" + std::to_string(suffix));
    std::filesystem::create_directories(path_);
  }
  ~TemporaryDirectory() { std::filesystem::remove_all(path_); }
  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

Receipt sampleReceipt(uint64_t shard_index = 3) {
  Receipt receipt;
  receipt.file_id = "receipt-file";
  receipt.version = 5;
  receipt.challenge_id[0] = 0x11;
  receipt.nonce = common::Bytes(32, 0x22);
  receipt.shard_index = shard_index;
  receipt.stripe_index = shard_index / 6;
  receipt.result = VerificationOutcome::Verified;
  receipt.original_root[0] = 0x33;
  receipt.repair = RepairOutcome::NotAttempted;
  receipt.evidence_digest[0] = 0x44;
  return receipt;
}

struct SignerFixture {
  std::optional<crypto::LiboqsSigner> signer;
  std::optional<crypto::SigningKeyPair> keys;

  explicit SignerFixture(const std::string& algorithm = "ML-DSA-44") {
    std::string error;
    signer = crypto::LiboqsSigner::create(algorithm, error);
    if (!signer.has_value()) throw std::runtime_error(error);
    keys = signer->generateKeyPair();
    if (!keys.has_value()) throw std::runtime_error("key generation failed");
  }
};

bool executeSql(const std::filesystem::path& path, const char* sql) {
  sqlite3* database = nullptr;
  if (sqlite3_open(path.c_str(), &database) != SQLITE_OK) {
    if (database != nullptr) sqlite3_close(database);
    return false;
  }
  const int status = sqlite3_exec(database, sql, nullptr, nullptr, nullptr);
  sqlite3_close(database);
  return status == SQLITE_OK;
}

}

TEST(Receipt, CanonicalRoundTripAndSignatureBindAllFields) {
  SignerFixture fixture;
  const auto receipt = sampleReceipt();
  const auto encoded = serialize(receipt);
  ASSERT_TRUE(encoded.has_value());
  const auto decoded = deserialize(*encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(*decoded, receipt);
  const auto signature = sign(receipt, *fixture.signer, *fixture.keys);
  ASSERT_TRUE(signature.has_value());
  EXPECT_TRUE(verify(receipt, *signature, *fixture.signer, fixture.keys->public_key));

  auto changed = receipt;
  ++changed.version;
  EXPECT_FALSE(verify(changed, *signature, *fixture.signer, fixture.keys->public_key));
  auto truncated = *encoded;
  truncated.pop_back();
  EXPECT_FALSE(deserialize(truncated).has_value());
}

TEST(AuditLog, AppendsSignedReceiptsAndVerifiesExternalCheckpoint) {
  TemporaryDirectory directory;
  SignerFixture fixture;
  std::string error;
  auto log = AuditLog::open(directory.path() / "audit.sqlite", error);
  ASSERT_TRUE(log.has_value()) << error;
  const auto checkpoint = directory.path() / "trusted-checkpoint.bin";
  ASSERT_TRUE(log->append(sampleReceipt(3), *fixture.signer, *fixture.keys, checkpoint, error))
      << error;
  const auto second = sampleReceipt(4);
  const auto second_signature = sign(second, *fixture.signer, *fixture.keys);
  ASSERT_TRUE(second_signature.has_value());
  ASSERT_TRUE(log->appendSigned(second, *second_signature, *fixture.signer,
                                fixture.keys->public_key, checkpoint, error))
      << error;
  EXPECT_TRUE(log->verify(checkpoint, *fixture.signer, fixture.keys->public_key, error)) << error;
}

TEST(AuditLog, RejectsInvalidPreSignedReceipt) {
  TemporaryDirectory directory;
  SignerFixture fixture;
  std::string error;
  auto log = AuditLog::open(directory.path() / "invalid-presigned.sqlite", error);
  ASSERT_TRUE(log.has_value()) << error;
  const auto receipt = sampleReceipt();
  common::Bytes forged_signature(2420, 0);
  EXPECT_FALSE(log->appendSigned(receipt, forged_signature, *fixture.signer,
                                 fixture.keys->public_key,
                                 directory.path() / "invalid-presigned-checkpoint.bin", error));
}

TEST(AuditLog, RejectsEditedEntryAndForgedReceipt) {
  TemporaryDirectory directory;
  SignerFixture trusted;
  std::string error;
  auto log = AuditLog::open(directory.path() / "edited.sqlite", error);
  ASSERT_TRUE(log.has_value());
  const auto checkpoint = directory.path() / "edited-checkpoint.bin";
  ASSERT_TRUE(log->append(sampleReceipt(), *trusted.signer, *trusted.keys, checkpoint, error));
  ASSERT_TRUE(executeSql(directory.path() / "edited.sqlite",
                         "UPDATE entries SET payload=x'00' WHERE sequence=1"));
  EXPECT_FALSE(log->verify(checkpoint, *trusted.signer, trusted.keys->public_key, error));

  SignerFixture attacker;
  auto forged_log = AuditLog::open(directory.path() / "forged.sqlite", error);
  ASSERT_TRUE(forged_log.has_value());
  const auto forged_checkpoint = directory.path() / "forged-checkpoint.bin";
  ASSERT_TRUE(forged_log->append(sampleReceipt(), *attacker.signer, *attacker.keys,
                                  forged_checkpoint, error));
  EXPECT_FALSE(forged_log->verify(forged_checkpoint, *trusted.signer,
                                  trusted.keys->public_key, error));
}

TEST(AuditLog, DetectsDeletedMiddleEntryAndRollbackToOlderPrefix) {
  TemporaryDirectory directory;
  SignerFixture fixture;
  std::string error;
  auto log = AuditLog::open(directory.path() / "rollback.sqlite", error);
  ASSERT_TRUE(log.has_value());
  const auto checkpoint = directory.path() / "rollback-checkpoint.bin";
  ASSERT_TRUE(log->append(sampleReceipt(1), *fixture.signer, *fixture.keys, checkpoint, error));
  ASSERT_TRUE(log->append(sampleReceipt(2), *fixture.signer, *fixture.keys, checkpoint, error));
  ASSERT_TRUE(log->append(sampleReceipt(3), *fixture.signer, *fixture.keys, checkpoint, error));
  ASSERT_TRUE(executeSql(directory.path() / "rollback.sqlite",
                         "DELETE FROM entries WHERE sequence=2"));
  EXPECT_FALSE(log->verify(checkpoint, *fixture.signer, fixture.keys->public_key, error));
}

TEST(AuditLog, DetectsOlderValidLogAgainstCurrentCheckpoint) {
  TemporaryDirectory directory;
  SignerFixture fixture;
  std::string error;
  const auto database_path = directory.path() / "prefix.sqlite";
  const auto checkpoint = directory.path() / "prefix-checkpoint.bin";
  auto log = AuditLog::open(database_path, error);
  ASSERT_TRUE(log.has_value());
  ASSERT_TRUE(log->append(sampleReceipt(1), *fixture.signer, *fixture.keys, checkpoint, error));
  ASSERT_TRUE(log->append(sampleReceipt(2), *fixture.signer, *fixture.keys, checkpoint, error));
  ASSERT_TRUE(executeSql(database_path, "DELETE FROM entries WHERE sequence>1"));
  EXPECT_FALSE(log->verify(checkpoint, *fixture.signer, fixture.keys->public_key, error));
}

TEST(AuditLog, RejectsMissingAndCorruptedExternalCheckpoint) {
  TemporaryDirectory directory;
  SignerFixture fixture;
  std::string error;
  auto log = AuditLog::open(directory.path() / "checkpoint.sqlite", error);
  ASSERT_TRUE(log.has_value()) << error;
  const auto checkpoint = directory.path() / "checkpoint.bin";
  ASSERT_TRUE(log->append(sampleReceipt(), *fixture.signer, *fixture.keys, checkpoint, error))
      << error;
  const auto saved = directory.path() / "saved-checkpoint.bin";
  std::filesystem::copy_file(checkpoint, saved);
  std::filesystem::remove(checkpoint);
  EXPECT_FALSE(log->verify(checkpoint, *fixture.signer, fixture.keys->public_key, error));
  std::filesystem::copy_file(saved, checkpoint);
  {
    std::fstream file(checkpoint, std::ios::binary | std::ios::in | std::ios::out);
    ASSERT_TRUE(file.good());
    file.seekp(0);
    file.put(static_cast<char>(0xff));
  }
  EXPECT_FALSE(log->verify(checkpoint, *fixture.signer, fixture.keys->public_key, error));
}

TEST(Gate4, RiskSamplingProducesSignedReceiptsAndCurrentCheckpoint) {
  TemporaryDirectory directory;
  SignerFixture fixture;
  audit::RiskConfig risk;
  risk.decay_window = 10;
  std::vector<audit::RiskCounts> risks(10);
  risks[8].failures = 5;
  std::string error;
  const auto baseline = audit::createChallenge("gate4-file", 9, 40, 5, error);
  ASSERT_TRUE(baseline.has_value()) << error;
  const auto challenge = audit::selectSupplemental(*baseline, 40, 4, risks, 3, risk, error);
  ASSERT_TRUE(challenge.has_value()) << error;
  ASSERT_EQ(challenge->indices.size(), baseline->indices.size() + 3);
  for (const auto index : baseline->indices) {
    EXPECT_NE(std::find(challenge->indices.begin(), challenge->indices.end(), index),
              challenge->indices.end());
  }

  auto log = AuditLog::open(directory.path() / "gate4.sqlite", error);
  ASSERT_TRUE(log.has_value()) << error;
  const auto checkpoint = directory.path() / "gate4-checkpoint.bin";
  for (const auto index : challenge->indices) {
    auto receipt = sampleReceipt(index);
    receipt.file_id = challenge->file_id;
    receipt.version = challenge->version;
    receipt.challenge_id = challenge->id;
    receipt.nonce = challenge->nonce;
    receipt.shard_index = index;
    receipt.stripe_index = index / 4;
    ASSERT_TRUE(log->append(receipt, *fixture.signer, *fixture.keys, checkpoint, error)) << error;
  }
  EXPECT_TRUE(log->verify(checkpoint, *fixture.signer, fixture.keys->public_key, error)) << error;
}

}
