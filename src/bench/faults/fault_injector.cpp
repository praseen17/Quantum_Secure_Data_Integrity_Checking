#include "qsafe/bench/faults/fault_injector.hpp"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <limits>
#include <set>
#include <unordered_set>

namespace qsafe::bench::faults {

namespace {

constexpr uint64_t kMaximumFaultCount = 1000000;

}

FaultInjector::FaultInjector(uint64_t seed) : random_(seed) {}

std::optional<std::vector<uint64_t>> FaultInjector::choose(uint64_t population, uint64_t count) {
  if (count > population || count > kMaximumFaultCount) return std::nullopt;
  std::unordered_set<uint64_t> selected;
  selected.reserve(static_cast<size_t>(count));
  for (uint64_t next = population - count; next < population; ++next) {
    std::uniform_int_distribution<uint64_t> distribution(0, next);
    const uint64_t candidate = distribution(random_);
    if (!selected.insert(candidate).second) selected.insert(next);
  }
  std::vector<uint64_t> result(selected.begin(), selected.end());
  std::sort(result.begin(), result.end());
  return result;
}

std::optional<uint64_t> FaultInjector::stripeBase(uint64_t stripe_count, uint64_t stripe_index,
                                                   uint32_t data_shards,
                                                   uint32_t parity_shards) {
  const uint64_t width = static_cast<uint64_t>(data_shards) + parity_shards;
  if (data_shards == 0 || parity_shards == 0 || width > UINT32_MAX ||
      stripe_count > std::numeric_limits<uint64_t>::max() / width ||
      stripe_index >= stripe_count) {
    return std::nullopt;
  }
  return stripe_index * width;
}

std::optional<FaultSchedule> FaultInjector::singleCorruption(uint64_t shard_count, uint64_t index) {
  if (shard_count == 0 || index >= shard_count) return std::nullopt;
  return FaultSchedule{{{index, FaultKind::Corrupt}}, std::nullopt};
}

std::optional<FaultSchedule> FaultInjector::clusteredCorruption(
    uint64_t stripe_count, uint32_t data_shards, uint32_t parity_shards, uint64_t stripe_index,
    uint32_t count) {
  const auto base = stripeBase(stripe_count, stripe_index, data_shards, parity_shards);
  const uint64_t width = static_cast<uint64_t>(data_shards) + parity_shards;
  if (!base.has_value() || count == 0 || count > width) return std::nullopt;
  const auto local_indices = choose(width, count);
  if (!local_indices.has_value()) return std::nullopt;
  FaultSchedule schedule;
  for (const uint64_t index : *local_indices) {
    schedule.events.push_back({*base + index, FaultKind::Corrupt});
  }
  return schedule;
}

std::optional<FaultSchedule> FaultInjector::randomCorruption(uint64_t shard_count,
                                                              double fraction) {
  if (shard_count == 0 || !std::isfinite(fraction) || fraction < 0.0 || fraction > 1.0) {
    return std::nullopt;
  }
  const long double product = static_cast<long double>(shard_count) * fraction;
  const long double tolerance = 4.0L * DBL_EPSILON * std::max(1.0L, std::abs(product));
  const long double requested = std::floor(product + tolerance);
  if (requested > kMaximumFaultCount) return std::nullopt;
  const auto indices = choose(shard_count, static_cast<uint64_t>(requested));
  if (!indices.has_value()) return std::nullopt;
  FaultSchedule schedule;
  for (const uint64_t index : *indices) schedule.events.push_back({index, FaultKind::Corrupt});
  return schedule;
}

std::optional<FaultSchedule> FaultInjector::deletion(uint64_t shard_count, uint64_t count) {
  if (shard_count == 0 || count == 0) return std::nullopt;
  const auto indices = choose(shard_count, count);
  if (!indices.has_value()) return std::nullopt;
  FaultSchedule schedule;
  for (const uint64_t index : *indices) schedule.events.push_back({index, FaultKind::Delete});
  return schedule;
}

std::optional<FaultSchedule> FaultInjector::parityCorruption(
    uint64_t stripe_count, uint32_t data_shards, uint32_t parity_shards, uint64_t stripe_index,
    uint32_t parity_index) {
  const auto base = stripeBase(stripe_count, stripe_index, data_shards, parity_shards);
  if (!base.has_value() || parity_index >= parity_shards) return std::nullopt;
  return FaultSchedule{{{*base + data_shards + parity_index, FaultKind::Corrupt}}, std::nullopt};
}

std::optional<std::vector<FaultSchedule>> FaultInjector::repeatedStripeFailures(
    uint64_t stripe_count, uint32_t data_shards, uint32_t parity_shards, uint64_t stripe_index,
    const std::vector<uint32_t>& local_indices, uint32_t rounds) {
  const auto base = stripeBase(stripe_count, stripe_index, data_shards, parity_shards);
  const uint64_t width = static_cast<uint64_t>(data_shards) + parity_shards;
  if (!base.has_value() || local_indices.empty() || rounds == 0 || rounds > 100000 ||
      local_indices.size() > width) {
    return std::nullopt;
  }
  std::set<uint32_t> unique;
  for (const uint32_t index : local_indices) {
    if (index >= width || !unique.insert(index).second) return std::nullopt;
  }
  FaultSchedule schedule;
  for (const uint32_t index : local_indices) {
    schedule.events.push_back({*base + index, FaultKind::Corrupt});
  }
  return std::vector<FaultSchedule>(rounds, schedule);
}

std::optional<FaultSchedule> FaultInjector::beyondRecoverability(uint64_t stripe_index,
                                                                  uint32_t data_shards,
                                                                  uint32_t parity_shards) {
  const uint64_t width = static_cast<uint64_t>(data_shards) + parity_shards;
  if (width == 0) return std::nullopt;
  const auto base = stripeBase(std::numeric_limits<uint64_t>::max() / width, stripe_index,
                               data_shards, parity_shards);
  if (!base.has_value()) return std::nullopt;
  const uint64_t count = static_cast<uint64_t>(parity_shards) + 1;
  const auto local_indices = choose(static_cast<uint64_t>(data_shards) + parity_shards, count);
  if (!local_indices.has_value()) return std::nullopt;
  FaultSchedule schedule;
  for (const uint64_t index : *local_indices) {
    schedule.events.push_back({*base + index, FaultKind::Corrupt});
  }
  return schedule;
}

std::optional<FaultSchedule> FaultInjector::staleManifestReplay(uint64_t version) const {
  if (version == 0) return std::nullopt;
  FaultSchedule schedule;
  schedule.stale_manifest_version = version;
  return schedule;
}

bool FaultInjector::apply(storage::CloudStorage& cloud, const std::string& file_id,
                          uint64_t version, const FaultSchedule& schedule,
                          std::string& error) const {
  std::set<uint64_t> indices;
  for (const auto& event : schedule.events) {
    if (!indices.insert(event.index).second) {
      error = "fault schedule contains duplicate shard indices";
      return false;
    }
  }
  for (const auto& event : schedule.events) {
    if (event.kind == FaultKind::Delete) {
      if (!cloud.setAvailability(file_id, version, event.index,
                                 storage::ShardAvailability::Unavailable, error)) {
        return false;
      }
      continue;
    }
    const auto shard = cloud.getShard(file_id, version, event.index);
    if (shard.status != storage::ReadStatus::Available) {
      error = "cannot corrupt an unavailable shard";
      return false;
    }
    auto damaged = shard.bytes;
    if (damaged.empty()) {
      damaged.push_back(1);
    } else {
      damaged[0] ^= 1;
    }
    if (!cloud.injectFaultShardBytes(file_id, version, event.index, damaged, error)) return false;
  }
  error.clear();
  return true;
}

}
