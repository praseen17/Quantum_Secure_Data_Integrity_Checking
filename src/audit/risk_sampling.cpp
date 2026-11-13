#include "qsafe/audit/risk_sampling.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <fstream>
#include <limits>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace qsafe::audit {

namespace {

constexpr uint64_t kMaximumRiskShardCount = 1000000;
constexpr uint64_t kMaximumDecayWindow = 1000000;

std::string trim(std::string value) {
  const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char character) {
    return std::isspace(character) != 0;
  });
  const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char character) {
                    return std::isspace(character) != 0;
                  }).base();
  if (first >= last) return {};
  return std::string(first, last);
}

std::optional<double> parseDouble(const std::string& value) {
  try {
    size_t used = 0;
    const double parsed = std::stod(value, &used);
    if (used != value.size() || !std::isfinite(parsed)) return std::nullopt;
    return parsed;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<uint64_t> parseUnsigned(const std::string& value) {
  if (value.empty() || value.front() == '-') return std::nullopt;
  try {
    size_t used = 0;
    const auto parsed = std::stoull(value, &used);
    if (used != value.size()) return std::nullopt;
    return parsed;
  } catch (...) {
    return std::nullopt;
  }
}

struct WeightedIndex {
  long double key;
  uint64_t index;
};

std::optional<long double> exponentialKey(double weight) {
  std::array<uint8_t, sizeof(uint64_t)> bytes{};
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) return std::nullopt;
  uint64_t random_value = 0;
  for (const uint8_t byte : bytes) random_value = (random_value << 8) | byte;
  const uint64_t mantissa = random_value >> 11;
  constexpr long double scale = 9007199254740992.0L;
  const long double unit = (static_cast<long double>(mantissa) + 0.5L) / scale;
  return -std::log(unit) / static_cast<long double>(weight);
}

}

std::optional<RiskConfig> RiskConfig::load(const std::filesystem::path& path,
                                           std::string& error) {
  std::ifstream input(path);
  if (!input) {
    error = "risk configuration could not be opened";
    return std::nullopt;
  }

  RiskConfig config;
  std::unordered_map<std::string, std::string> values;
  std::string line;
  while (std::getline(input, line)) {
    line = trim(std::move(line));
    if (line.empty()) continue;
    const auto separator = line.find('=');
    if (separator == std::string::npos) {
      error = "risk configuration line is missing '='";
      return std::nullopt;
    }
    const auto key = trim(line.substr(0, separator));
    const auto value = trim(line.substr(separator + 1));
    if (key.empty() || value.empty() || !values.emplace(key, value).second) {
      error = "risk configuration contains an empty or duplicate field";
      return std::nullopt;
    }
  }
  if (input.bad()) {
    error = "risk configuration read failed";
    return std::nullopt;
  }
  if (values.size() != 5 || values.find("alpha") == values.end() ||
      values.find("beta") == values.end() || values.find("gamma") == values.end() ||
      values.find("epsilon") == values.end() || values.find("decay_window") == values.end()) {
    error = "risk configuration must define alpha, beta, gamma, epsilon, and decay_window";
    return std::nullopt;
  }

  const auto alpha_value = parseDouble(values.at("alpha"));
  const auto beta_value = parseDouble(values.at("beta"));
  const auto gamma_value = parseDouble(values.at("gamma"));
  const auto epsilon_value = parseDouble(values.at("epsilon"));
  const auto window_value = parseUnsigned(values.at("decay_window"));
  if (!alpha_value || !beta_value || !gamma_value || !epsilon_value || !window_value) {
    error = "risk configuration contains an invalid number";
    return std::nullopt;
  }
  config.alpha = *alpha_value;
  config.beta = *beta_value;
  config.gamma = *gamma_value;
  config.epsilon = *epsilon_value;
  config.decay_window = *window_value;
  if (!config.valid()) {
    error = "risk weights must be nonnegative and sum to one; epsilon and decay window must be positive";
    return std::nullopt;
  }
  error.clear();
  return config;
}

bool RiskConfig::valid() const {
  if (!std::isfinite(alpha) || !std::isfinite(beta) || !std::isfinite(gamma) ||
      !std::isfinite(epsilon) || alpha < 0.0 || beta < 0.0 || gamma < 0.0 ||
      epsilon <= 0.0 || epsilon > 1.0 || decay_window == 0 ||
      decay_window > kMaximumDecayWindow) {
    return false;
  }
  const double sum = alpha + beta + gamma;
  return std::abs(sum - 1.0) <= 1e-9;
}

std::optional<double> RiskConfig::score(const RiskCounts& counts) const {
  if (!valid()) return std::nullopt;
  const auto normalize = [this](uint64_t count) {
    return std::min(1.0, static_cast<double>(count) / decay_window);
  };
  const double value = alpha * normalize(counts.failures) + beta * normalize(counts.repairs) +
                       gamma * normalize(counts.anomalies);
  if (!std::isfinite(value) || value < 0.0 || value > 1.0) return std::nullopt;
  return value;
}

std::optional<Challenge> selectSupplemental(const Challenge& baseline, uint64_t shard_count,
                                             uint32_t stripe_width,
                                             const std::vector<RiskCounts>& stripe_risks,
                                             uint32_t supplemental_count,
                                             const RiskConfig& config, std::string& error) {
  if (!config.valid() || shard_count == 0 || shard_count > kMaximumRiskShardCount ||
      stripe_width == 0 || baseline.indices.size() > shard_count) {
    error = "invalid risk sampling parameters";
    return std::nullopt;
  }
  const uint64_t stripe_count = shard_count / stripe_width + (shard_count % stripe_width != 0);
  if (stripe_risks.size() != stripe_count) {
    error = "risk record count does not match shard stripes";
    return std::nullopt;
  }
  const auto validated_baseline = extendChallenge(baseline, {}, error);
  if (!validated_baseline.has_value()) return std::nullopt;
  std::set<uint64_t> selected;
  for (const uint64_t index : baseline.indices) {
    if (index >= shard_count) {
      error = "baseline challenge contains an out-of-range index";
      return std::nullopt;
    }
    selected.insert(index);
  }
  if (supplemental_count == 0) {
    error.clear();
    return baseline;
  }

  const uint64_t candidate_count = shard_count - selected.size();
  const uint64_t extra_count = std::min<uint64_t>(supplemental_count, candidate_count);
  if (extra_count == 0) {
    error.clear();
    return baseline;
  }

  std::vector<WeightedIndex> candidates;
  candidates.reserve(static_cast<size_t>(candidate_count));
  for (uint64_t index = 0; index < shard_count; ++index) {
    if (selected.find(index) != selected.end()) continue;
    const auto score_value = config.score(stripe_risks[index / stripe_width]);
    if (!score_value.has_value()) {
      error = "risk score calculation failed";
      return std::nullopt;
    }
    const auto key = exponentialKey(*score_value + config.epsilon);
    if (!key.has_value()) {
      error = "operating system CSPRNG failed during risk sampling";
      return std::nullopt;
    }
    candidates.push_back({*key, index});
  }
  if (candidates.size() != candidate_count) {
    error = "risk candidate count mismatch";
    return std::nullopt;
  }
  std::sort(candidates.begin(), candidates.end(), [](const WeightedIndex& left,
                                                      const WeightedIndex& right) {
    if (left.key != right.key) return left.key < right.key;
    return left.index < right.index;
  });
  std::vector<uint64_t> supplemental;
  supplemental.reserve(static_cast<size_t>(extra_count));
  for (uint64_t i = 0; i < extra_count; ++i) supplemental.push_back(candidates[i].index);
  return extendChallenge(baseline, supplemental, error);
}

}
