#include "qsafe/audit/risk_sampling.hpp"
#include "qsafe/bench/faults/fault_injector.hpp"
#include "qsafe/merkle/merkle_tree.hpp"
#include "qsafe/receipts/audit_log.hpp"
#include "qsafe/repair/commitment_repair.hpp"
#include "qsafe/repair/reed_solomon_codec.hpp"
#include "qsafe/storage/chunker.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <ctime>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <random>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
constexpr size_t kShardSize = qsafe::storage::FileChunker::kDefaultShardSize;
constexpr uint32_t kDataShards = 4;
constexpr uint32_t kParityShards = 2;
constexpr uint32_t kStripeWidth = kDataShards + kParityShards;

struct Options {
  uint64_t size_mb = 10;
  uint32_t repetitions = 1;
  uint32_t rounds = 10;
  double sample_fraction = 0.05;
  double corruption_fraction = 0.02;
  uint64_t seed = 20261112;
  std::string pattern = "localized";
  std::filesystem::path risk_config = "config/risk.conf";
  std::filesystem::path work = std::filesystem::temp_directory_path() / "qsafe-bench";
};

double milliseconds(Clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

bool parse(int argc, char** argv, Options& options) {
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--help") {
      std::cout << "usage: qsafe_audit_experiment [--size-mb N] [--repetitions N] "
                   "[--rounds N] [--sample-fraction F] [--corruption-fraction F] "
                   "[--pattern localized|random] [--seed N] [--risk-config FILE] [--work DIR]\n";
      return false;
    }
    if (i + 1 >= argc) return false;
    const std::string value = argv[++i];
    try {
      if (argument == "--size-mb") options.size_mb = std::stoull(value);
      else if (argument == "--repetitions") options.repetitions = std::stoul(value);
      else if (argument == "--rounds") options.rounds = std::stoul(value);
      else if (argument == "--sample-fraction") options.sample_fraction = std::stod(value);
      else if (argument == "--corruption-fraction") options.corruption_fraction = std::stod(value);
      else if (argument == "--pattern") options.pattern = value;
      else if (argument == "--seed") options.seed = std::stoull(value);
      else if (argument == "--risk-config") options.risk_config = value;
      else if (argument == "--work") options.work = value;
      else return false;
    } catch (...) {
      return false;
    }
  }
  return options.size_mb > 0 && options.repetitions > 0 && options.rounds > 0 &&
         options.sample_fraction > 0.0 && options.sample_fraction <= 1.0 &&
         options.corruption_fraction > 0.0 && options.corruption_fraction <= 1.0 &&
         (options.pattern == "localized" || options.pattern == "random");
}

struct Ingested {
  std::optional<qsafe::storage::CloudStorage> cloud;
  qsafe::manifest::Manifest manifest;
  qsafe::common::Bytes signature;
  qsafe::crypto::SigningKeyPair owner_keys;
  std::vector<qsafe::common::Bytes> shards;
  uint64_t original_bytes = 0;
  uint64_t metadata_bytes = 0;
};

std::optional<Ingested> ingest(const Options& options, const std::string& file_id,
                               uint64_t version, uint64_t seed,
                               const std::filesystem::path& root,
                               const qsafe::crypto::LiboqsSigner& signer,
                               std::string& error) {
  using namespace qsafe;
  constexpr uint64_t mib = 1024 * 1024;
  if (options.size_mb > std::numeric_limits<uint64_t>::max() / mib) return std::nullopt;
  const uint64_t input_size = options.size_mb * mib;
  const uint64_t stripe_data_bytes = kDataShards * kShardSize;
  const uint64_t stripe_count = (input_size + stripe_data_bytes - 1) / stripe_data_bytes;
  if (stripe_count == 0 || stripe_count > 1000000) return std::nullopt;

  auto cloud = storage::CloudStorage::open(root, error);
  auto codec = repair::ReedSolomonCodec::create(kDataShards, kParityShards, error);
  auto keys = signer.generateKeyPair();
  if (!cloud || !codec || !keys) return std::nullopt;
  Ingested result;
  result.cloud = std::move(cloud);
  result.owner_keys = std::move(*keys);
  result.original_bytes = input_size;
  std::mt19937_64 random(seed);
  std::vector<crypto::Hash> leaves;
  result.shards.reserve(stripe_count * kStripeWidth);
  for (uint64_t stripe = 0; stripe < stripe_count; ++stripe) {
    std::vector<common::Bytes> data(kDataShards, common::Bytes(kShardSize));
    for (auto& shard : data) {
      for (auto& byte : shard) byte = static_cast<uint8_t>(random());
    }
    const auto parity = codec->encodeStripe(data);
    if (!parity) return std::nullopt;
    for (auto& shard : data) result.shards.push_back(std::move(shard));
    result.shards.insert(result.shards.end(), parity->begin(), parity->end());
  }
  result.manifest.file_id = file_id;
  result.manifest.version = version;
  result.manifest.shard_count = result.shards.size();
  result.manifest.data_shards = kDataShards;
  result.manifest.parity_shards = kParityShards;
  result.manifest.codec = "ISA-L-RS";
  result.manifest.hash_id = "SHA-256";
  result.manifest.protocol_version = 1;
  for (size_t i = 0; i < result.shards.size(); ++i) {
    const auto leaf = crypto::leafHash(file_id, version, i, result.shards[i]);
    if (!leaf) return std::nullopt;
    leaves.push_back(*leaf);
  }
  const auto tree = merkle::MerkleTree::build(leaves);
  if (!tree) return std::nullopt;
  result.manifest.root = tree->root();
  std::vector<std::vector<crypto::Hash>> paths;
  paths.reserve(leaves.size());
  for (size_t i = 0; i < leaves.size(); ++i) {
    const auto path = tree->path(i);
    if (!path) return std::nullopt;
    result.metadata_bytes += path->size() * crypto::Hash{}.size();
    paths.push_back(*path);
  }
  const auto signature = manifest::sign(result.manifest, signer, result.owner_keys);
  if (!signature || !result.cloud->put(file_id, version, result.shards, paths, error)) {
    return std::nullopt;
  }
  result.signature = *signature;
  return result;
}

bool applyDamage(Ingested& ingest, const Options& options, uint64_t seed,
                 const std::string& file_id, uint64_t version, std::string& error) {
  qsafe::bench::faults::FaultInjector faults(seed);
  std::optional<qsafe::bench::faults::FaultSchedule> schedule;
  if (options.pattern == "localized") {
    const uint64_t stripe_count = ingest.shards.size() / kStripeWidth;
    if (stripe_count == 0) return false;
    schedule = faults.singleCorruption(ingest.shards.size(), (stripe_count / 2) * kStripeWidth);
  } else {
    schedule = faults.randomCorruption(ingest.shards.size(), options.corruption_fraction);
  }
  return schedule && faults.apply(*ingest.cloud, file_id, version, *schedule, error);
}

struct Strategy {
  const char* name;
  bool adaptive;
  bool repair;
  bool risk_only;
  bool receipt_log;
};

constexpr Strategy kStrategies[] = {{"B1_uniform", false, false, false, false},
                                     {"B2_uniform_repair", false, true, false, false},
                                     {"B3_risk_diagnostic", true, false, true, false},
                                     {"QSAFE_full", true, true, false, true}};

bool runCell(const Options& options, const Strategy& strategy, uint32_t repetition,
             std::ofstream& csv, std::string& error) {
  using namespace qsafe;
  const uint64_t seed = options.seed + repetition;
  const std::string file_id = std::string("bench-") + strategy.name + "-" +
                              std::to_string(repetition);
  const uint64_t version = 1;
  const auto root = options.work / (strategy.name + std::string("-") + std::to_string(repetition));
  std::filesystem::remove_all(root);
  auto signer_value = crypto::LiboqsSigner::create("ML-DSA-44", error);
  if (!signer_value) return false;
  auto signer = *signer_value;
  const auto ingest_start = Clock::now();
  auto stored = ingest(options, file_id, version, seed, root, signer, error);
  const double ingest_ms = milliseconds(Clock::now() - ingest_start);
  if (!stored || !applyDamage(*stored, options, seed, file_id, version, error)) return false;

  const uint64_t shard_count = stored->manifest.shard_count;
  const double actual_corruption_fraction = options.pattern == "localized"
      ? 1.0 / static_cast<double>(shard_count) : options.corruption_fraction;
  const uint32_t total_samples = std::max<uint32_t>(1, static_cast<uint32_t>(
      std::ceil(shard_count * options.sample_fraction)));
  const uint32_t base_samples = strategy.adaptive && !strategy.risk_only
                                    ? std::max<uint32_t>(1, total_samples / 2)
                                    : strategy.risk_only ? 1 : total_samples;
  const uint32_t supplemental = strategy.adaptive
                                    ? (strategy.risk_only ? total_samples - base_samples
                                                          : total_samples - base_samples)
                                    : 0;
  std::vector<audit::RiskCounts> risks((shard_count + kStripeWidth - 1) / kStripeWidth);
  const auto loaded_risk_config = audit::RiskConfig::load(options.risk_config, error);
  if (!loaded_risk_config) return false;
  const audit::RiskConfig risk_config = *loaded_risk_config;
  audit::TrustedCheckpoint checkpoint{file_id, version};
  std::optional<receipts::AuditLog> receipt_log;
  const auto checkpoint_path = root / "external-checkpoint.bin";
  if (strategy.receipt_log) {
    receipt_log = receipts::AuditLog::open(root / "receipts.sqlite", error);
    if (!receipt_log) return false;
  }
  uint32_t detected_round = 0;
  uint64_t audit_bytes = 0;
  uint64_t repair_bytes = 0;
  double total_wall_ms = 0.0;
  double total_cpu_ms = 0.0;
  double signature_ms = 0.0;
  double verify_ms = 0.0;
  bool any_repair_succeeded = false;

  for (uint32_t round = 1; round <= options.rounds; ++round) {
    std::optional<audit::Challenge> baseline;
    if (strategy.risk_only) {
      baseline = audit::createChallenge(file_id, version, shard_count, 1, error);
    } else {
      baseline = audit::createChallenge(file_id, version, shard_count, base_samples, error);
    }
    if (!baseline) return false;
    std::optional<audit::Challenge> challenge = *baseline;
    if (strategy.adaptive && supplemental > 0) {
      challenge = audit::selectSupplemental(*baseline, shard_count, kStripeWidth, risks,
                                             supplemental, risk_config, error);
      if (!challenge) return false;
    }

    const auto wall_start = Clock::now();
    const auto cpu_start = std::clock();
    const auto response = audit::makeResponse(*challenge, *stored->cloud);
    const auto audit_result = audit::verifyResponse(stored->manifest, stored->signature, signer,
        stored->owner_keys.public_key, checkpoint, *challenge, response);
    if (!audit_result.manifest_valid || !audit_result.checkpoint_valid ||
        !audit_result.challenge_valid) return false;
    std::vector<uint64_t> failed;
    uint64_t round_repair_bytes = 0;
    bool repaired_this_round = false;
    signature_ms = 0.0;
    verify_ms = 0.0;
    uint64_t transferred = 0;
    for (const auto& shard_result : audit_result.shards) {
      const auto found = std::find_if(response.shards.begin(), response.shards.end(),
          [&shard_result](const audit::AuditedShard& shard) { return shard.index == shard_result.index; });
      if (found != response.shards.end()) {
        transferred += found->bytes.size() + found->proof.size() * crypto::Hash{}.size();
      }
      if (shard_result.result != audit::ShardResultCode::Verified) {
        failed.push_back(shard_result.index);
        ++risks[shard_result.index / kStripeWidth].failures;
      }
    }
    audit_bytes += transferred;
    if (!failed.empty() && detected_round == 0) detected_round = round;
    if (strategy.receipt_log) for (const auto index : challenge->indices) {
      receipts::Receipt receipt;
      receipt.file_id = file_id;
      receipt.version = version;
      receipt.challenge_id = challenge->id;
      receipt.nonce = challenge->nonce;
      receipt.shard_index = index;
      receipt.stripe_index = index / kStripeWidth;
      receipt.result = receipts::VerificationOutcome::Inconclusive;
      const auto result = std::find_if(audit_result.shards.begin(), audit_result.shards.end(),
          [index](const audit::ShardResult& item) { return item.index == index; });
      if (result != audit_result.shards.end() && result->result == audit::ShardResultCode::Verified) {
        receipt.result = receipts::VerificationOutcome::Verified;
      } else if (result != audit_result.shards.end() && result->result == audit::ShardResultCode::Corrupt) {
        receipt.result = receipts::VerificationOutcome::Corrupt;
      } else if (result != audit_result.shards.end() && result->result == audit::ShardResultCode::Unavailable) {
        receipt.result = receipts::VerificationOutcome::Unavailable;
      }
      receipt.original_root = stored->manifest.root;
      const auto signing_start = Clock::now();
      const auto receipt_signature = receipts::sign(receipt, signer, stored->owner_keys);
      signature_ms += milliseconds(Clock::now() - signing_start);
      if (!receipt_signature) return false;
      if (receipt_log) {
        uint64_t verification_nanoseconds = 0;
        if (!receipt_log->appendSigned(receipt, *receipt_signature, signer,
                stored->owner_keys.public_key, checkpoint_path, error,
                &verification_nanoseconds)) return false;
        verify_ms += static_cast<double>(verification_nanoseconds) / 1000000.0;
      }
    }

    if (receipt_log && !receipt_log->verify(checkpoint_path, signer,
                                             stored->owner_keys.public_key, error)) return false;

    if (strategy.repair) {
      for (const auto index : failed) {
        const auto repair = repair::repairShard(stored->manifest, stored->signature, signer,
            stored->owner_keys.public_key, checkpoint, *stored->cloud, index);
        if (repair.repaired()) {
          repaired_this_round = true;
          any_repair_succeeded = true;
          round_repair_bytes += repair.repair_bytes;
          repair_bytes += repair.repair_bytes;
          risks[index / kStripeWidth].repairs++;
        }
      }
    }

    const auto wall_end = Clock::now();
    const auto cpu_end = std::clock();
    total_wall_ms += milliseconds(wall_end - wall_start);
    total_cpu_ms += 1000.0 * static_cast<double>(cpu_end - cpu_start) / CLOCKS_PER_SEC;

    csv << strategy.name << ',' << options.pattern << ',' << repetition << ',' << round << ','
        << stored->original_bytes << ',' << shard_count << ',' << actual_corruption_fraction << ','
        << options.sample_fraction << ',' << challenge->indices.size() << ','
        << milliseconds(wall_end - wall_start) << ','
        << 1000.0 * static_cast<double>(cpu_end - cpu_start) / CLOCKS_PER_SEC << ','
        << transferred << ',' << (!failed.empty() ? 1 : 0) << ','
        << (repaired_this_round ? 1 : 0) << ',' << round_repair_bytes << ','
        << signature_ms << ',' << verify_ms << ','
        << std::accumulate(stored->shards.begin(), stored->shards.end(), uint64_t{0},
             [](uint64_t sum, const common::Bytes& shard) { return sum + shard.size(); }) << ','
        << stored->metadata_bytes << '\n';
  }
  (void)ingest_ms;
  (void)total_wall_ms;
  (void)total_cpu_ms;
  (void)any_repair_succeeded;
  stored->cloud.reset();
  std::error_code cleanup_error;
  std::filesystem::remove_all(root, cleanup_error);
  if (cleanup_error) {
    error = "failed to remove temporary benchmark store: " + cleanup_error.message();
    return false;
  }
  return csv.good();
}

}

int main(int argc, char** argv) {
  Options options;
  if (!parse(argc, argv, options)) return argc > 1 && std::string(argv[1]) == "--help" ? 0 : 2;
  std::error_code filesystem_error;
  std::filesystem::create_directories(options.work, filesystem_error);
  if (filesystem_error) return 2;
  std::cout << "strategy,pattern,repetition,round,file_bytes,shard_count,corruption_fraction,"
               "sample_fraction,sample_count,wall_ms,cpu_ms,bytes_transferred,detected,repair_success,"
               "repair_bytes,sign_ms,verify_ms,storage_bytes,metadata_bytes\n";
  for (const auto& strategy : kStrategies) {
    for (uint32_t repetition = 0; repetition < options.repetitions; ++repetition) {
      std::ofstream output(options.work / "cell.csv", std::ios::trunc);
      if (!output) return 2;
      std::string error;
      if (!runCell(options, strategy, repetition, output, error)) {
        std::cerr << "benchmark cell failed for " << strategy.name << " repetition "
                  << repetition << ": " << error << '\n';
        return 1;
      }
      output.close();
      std::ifstream cell(options.work / "cell.csv");
      std::string line;
      while (std::getline(cell, line)) std::cout << line << '\n';
      std::filesystem::remove(options.work / "cell.csv", filesystem_error);
    }
  }
  return 0;
}
