#pragma once

#include "qsafe/audit/audit.hpp"

#include <filesystem>
#include <optional>

namespace qsafe::audit {

struct RiskCounts {
  uint64_t failures = 0;
  uint64_t repairs = 0;
  uint64_t anomalies = 0;
};

struct RiskConfig {
  double alpha = 0.5;
  double beta = 0.3;
  double gamma = 0.2;
  double epsilon = 0.001;
  uint64_t decay_window = 10;

  static std::optional<RiskConfig> load(const std::filesystem::path& path, std::string& error);
  bool valid() const;
  std::optional<double> score(const RiskCounts& counts) const;
};

std::optional<Challenge> selectSupplemental(const Challenge& baseline, uint64_t shard_count,
                                             uint32_t stripe_width,
                                             const std::vector<RiskCounts>& stripe_risks,
                                             uint32_t supplemental_count,
                                             const RiskConfig& config, std::string& error);

}
