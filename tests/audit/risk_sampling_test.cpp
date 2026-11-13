#include "qsafe/audit/risk_sampling.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>

namespace qsafe::audit {

namespace {

class TemporaryConfig {
 public:
  TemporaryConfig() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    path_ = std::filesystem::temp_directory_path() /
            ("qsafe-risk-test-" + std::to_string(suffix) + ".conf");
  }
  ~TemporaryConfig() { std::filesystem::remove(path_); }
  void write(const std::string& value) {
    std::ofstream output(path_);
    output << value;
  }
  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

RiskConfig defaultConfig() {
  RiskConfig config;
  config.alpha = 0.5;
  config.beta = 0.3;
  config.gamma = 0.2;
  config.epsilon = 0.001;
  config.decay_window = 10;
  return config;
}

}

TEST(RiskConfig, ReadsWeightsEpsilonAndDecayWindow) {
  TemporaryConfig file;
  file.write("alpha=0.5\nbeta=0.3\ngamma=0.2\nepsilon=0.001\ndecay_window=10\n");
  std::string error;
  const auto config = RiskConfig::load(file.path(), error);
  ASSERT_TRUE(config.has_value()) << error;
  EXPECT_DOUBLE_EQ(config->alpha, 0.5);
  EXPECT_DOUBLE_EQ(config->beta, 0.3);
  EXPECT_DOUBLE_EQ(config->gamma, 0.2);
  EXPECT_DOUBLE_EQ(config->epsilon, 0.001);
  EXPECT_EQ(config->decay_window, 10U);
}

TEST(RiskConfig, RejectsMissingUnknownInvalidOrUnnormalizedValues) {
  TemporaryConfig file;
  std::string error;
  file.write("alpha=0.5\nbeta=0.3\ngamma=0.1\nepsilon=0.01\ndecay_window=10\n");
  EXPECT_FALSE(RiskConfig::load(file.path(), error).has_value());
  file.write("alpha=0.5\nbeta=0.3\ngamma=0.2\nepsilon=0\ndecay_window=10\n");
  EXPECT_FALSE(RiskConfig::load(file.path(), error).has_value());
  file.write("alpha=0.5\nbeta=0.3\ngamma=0.2\nepsilon=0.01\ndecay_window=0\n");
  EXPECT_FALSE(RiskConfig::load(file.path(), error).has_value());
  file.write("alpha=0.5\nbeta=0.3\ngamma=0.2\nepsilon=0.01\ndecay_window=10\nother=1\n");
  EXPECT_FALSE(RiskConfig::load(file.path(), error).has_value());
}

TEST(RiskConfig, NormalizesCountsOverDecayWindowAndClampsAtOne) {
  const auto config = defaultConfig();
  const auto partial = config.score({2, 1, 0});
  const auto clamped = config.score({100, 0, 0});
  const auto empty = config.score({0, 0, 0});
  ASSERT_TRUE(partial.has_value());
  ASSERT_TRUE(clamped.has_value());
  ASSERT_TRUE(empty.has_value());
  EXPECT_DOUBLE_EQ(*partial, 0.13);
  EXPECT_DOUBLE_EQ(*clamped, 0.5);
  EXPECT_DOUBLE_EQ(*empty, 0.0);
}

TEST(RiskSampling, PreservesBaselineWithoutDuplicatesAndZeroCrIsUnchanged) {
  const auto config = defaultConfig();
  std::string error;
  const auto baseline = createChallenge("risk-file", 3, 40, 5, error);
  ASSERT_TRUE(baseline.has_value()) << error;

  const std::vector<RiskCounts> risks(10);
  const auto unchanged = selectSupplemental(*baseline, 40, 4, risks, 0, config, error);
  ASSERT_TRUE(unchanged.has_value()) << error;
  EXPECT_EQ(unchanged->indices, baseline->indices);
  EXPECT_EQ(unchanged->nonce, baseline->nonce);
  EXPECT_EQ(unchanged->id, baseline->id);

  const auto extended = selectSupplemental(*baseline, 40, 4, risks, 8, config, error);
  ASSERT_TRUE(extended.has_value()) << error;
  ASSERT_EQ(extended->indices.size(), 13U);
  for (const uint64_t index : baseline->indices) {
    EXPECT_NE(std::find(extended->indices.begin(), extended->indices.end(), index),
              extended->indices.end());
  }
  const std::set<uint64_t> unique(extended->indices.begin(), extended->indices.end());
  EXPECT_EQ(unique.size(), extended->indices.size());
  EXPECT_NE(extended->id, baseline->id);
}

TEST(RiskSampling, HigherRiskStripesAreSelectedMoreOften) {
  auto config = defaultConfig();
  config.alpha = 1.0;
  config.beta = 0.0;
  config.gamma = 0.0;
  std::vector<RiskCounts> risks(10);
  risks[9].failures = config.decay_window;
  size_t high_risk_selected = 0;
  constexpr size_t trials = 500;
  for (size_t trial = 0; trial < trials; ++trial) {
    std::string error;
    const auto baseline = createChallenge("risk-file", 3, 40, 1, error);
    ASSERT_TRUE(baseline.has_value()) << error;
    const auto extended = selectSupplemental(*baseline, 40, 4, risks, 1, config, error);
    ASSERT_TRUE(extended.has_value()) << error;
    ASSERT_EQ(extended->indices.size(), 2U);
    if (extended->indices.back() / 4 == 9) ++high_risk_selected;
  }
  EXPECT_GT(high_risk_selected, trials * 0.9);
}

TEST(RiskSampling, RejectsInvalidBaselineAndRiskShapes) {
  const auto config = defaultConfig();
  std::string error;
  auto baseline = createChallenge("risk-file", 3, 40, 2, error);
  ASSERT_TRUE(baseline.has_value());
  auto malformed = *baseline;
  malformed.indices[1] = malformed.indices[0];
  EXPECT_FALSE(selectSupplemental(malformed, 40, 4, std::vector<RiskCounts>(10), 1, config,
                                  error)
                   .has_value());
  EXPECT_FALSE(selectSupplemental(*baseline, 40, 0, std::vector<RiskCounts>(10), 1, config,
                                  error)
                   .has_value());
  EXPECT_FALSE(selectSupplemental(*baseline, 40, 4, std::vector<RiskCounts>(9), 1, config,
                                  error)
                   .has_value());
}

}
