#pragma once

#include "qsafe/storage/cloud_store.hpp"

#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace qsafe::bench::faults {

enum class FaultKind { Corrupt, Delete };

struct FaultEvent {
  uint64_t index = 0;
  FaultKind kind = FaultKind::Corrupt;

  bool operator==(const FaultEvent& other) const {
    return index == other.index && kind == other.kind;
  }
};

struct FaultSchedule {
  std::vector<FaultEvent> events;
  std::optional<uint64_t> stale_manifest_version;
};

class FaultInjector {
 public:
  explicit FaultInjector(uint64_t seed);

  std::optional<FaultSchedule> singleCorruption(uint64_t shard_count, uint64_t index);
  std::optional<FaultSchedule> clusteredCorruption(uint64_t stripe_count, uint32_t data_shards,
                                                    uint32_t parity_shards, uint64_t stripe_index,
                                                    uint32_t count);
  std::optional<FaultSchedule> randomCorruption(uint64_t shard_count, double fraction);
  std::optional<FaultSchedule> deletion(uint64_t shard_count, uint64_t count);
  std::optional<FaultSchedule> parityCorruption(uint64_t stripe_count, uint32_t data_shards,
                                                uint32_t parity_shards, uint64_t stripe_index,
                                                uint32_t parity_index);
  std::optional<std::vector<FaultSchedule>> repeatedStripeFailures(
      uint64_t stripe_count, uint32_t data_shards, uint32_t parity_shards,
      uint64_t stripe_index, const std::vector<uint32_t>& local_indices, uint32_t rounds);
  std::optional<FaultSchedule> beyondRecoverability(uint64_t stripe_index, uint32_t data_shards,
                                                     uint32_t parity_shards);
  std::optional<FaultSchedule> staleManifestReplay(uint64_t version) const;
  bool apply(storage::CloudStorage& cloud, const std::string& file_id, uint64_t version,
             const FaultSchedule& schedule, std::string& error) const;

 private:
  std::optional<std::vector<uint64_t>> choose(uint64_t population, uint64_t count);
  static std::optional<uint64_t> stripeBase(uint64_t stripe_count, uint64_t stripe_index,
                                            uint32_t data_shards, uint32_t parity_shards);

  std::mt19937_64 random_;
};

}
