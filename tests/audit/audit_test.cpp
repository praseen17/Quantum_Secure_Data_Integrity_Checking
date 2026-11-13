#include "qsafe/audit/audit.hpp"

#include <gtest/gtest.h>

#include <cmath>
#include <algorithm>
#include <map>

namespace qsafe::audit {

TEST(AuditSampling, DetectionProbabilityMatchesHypergeometricFixtures) {
  EXPECT_NEAR(*detectionProbability(10, 2, 1), 0.2, 1e-12);
  EXPECT_NEAR(*detectionProbability(10, 2, 2), 17.0 / 45.0, 1e-12);
  EXPECT_NEAR(*detectionProbability(100, 5, 7), 0.30969590976034278, 1e-12);
  EXPECT_NEAR(*detectionProbability(30, 7, 12), 0.98436781609195401, 1e-12);
  EXPECT_EQ(*detectionProbability(10, 2, 0), 0.0);
  EXPECT_EQ(*detectionProbability(10, 2, 10), 1.0);
  EXPECT_EQ(*detectionProbability(10, 0, 10), 0.0);
}

TEST(AuditSampling, RejectsInvalidProbabilityParameters) {
  EXPECT_FALSE(detectionProbability(0, 0, 0).has_value());
  EXPECT_FALSE(detectionProbability(10, 11, 1).has_value());
  EXPECT_FALSE(detectionProbability(10, 1, 11).has_value());
  EXPECT_FALSE(baselineSampleSize(0, 0.1, 0.9).has_value());
  EXPECT_FALSE(baselineSampleSize(10, 0, 0.9).has_value());
  EXPECT_FALSE(baselineSampleSize(10, 0.1, 1).has_value());
  std::string error;
  EXPECT_FALSE(createChallenge("file", 1, 10, 0, error).has_value());
}

TEST(AuditSampling, BaselineIsSmallestSampleMeetingTarget) {
  const auto count = baselineSampleSize(10, 0.2, 0.9);
  ASSERT_TRUE(count.has_value());
  EXPECT_EQ(*count, 7U);
  EXPECT_GE(*detectionProbability(10, 2, *count), 0.9);
  EXPECT_LT(*detectionProbability(10, 2, *count - 1), 0.9);
}

TEST(AuditSampling, DetectionProbabilityIsMonotoneInSampleCount) {
  double previous = 0;
  for (uint64_t count = 0; count <= 30; ++count) {
    const auto probability = detectionProbability(30, 7, count);
    ASSERT_TRUE(probability.has_value());
    EXPECT_GE(*probability, previous);
    previous = *probability;
  }
}

TEST(AuditSampling, CsprngSamplerReturnsDistinctIndicesAndLooksUniform) {
  std::map<uint64_t, size_t> frequencies;
  constexpr size_t trials = 5000;
  for (size_t i = 0; i < trials; ++i) {
    std::string error;
    const auto challenge = createChallenge("uniformity", 1, 10, 1, error);
    ASSERT_TRUE(challenge.has_value()) << error;
    ASSERT_EQ(challenge->indices.size(), 1U);
    ++frequencies[challenge->indices.front()];
  }
  ASSERT_EQ(frequencies.size(), 10U);
  double chi_square = 0;
  const double expected = static_cast<double>(trials) / 10.0;
  for (uint64_t index = 0; index < 10; ++index) {
    const double difference = static_cast<double>(frequencies[index]) - expected;
    chi_square += difference * difference / expected;
  }
  EXPECT_LT(chi_square, 40.0);

  std::string error;
  const auto sample = createChallenge("distinct", 1, 100, 25, error);
  ASSERT_TRUE(sample.has_value()) << error;
  auto sorted = sample->indices;
  std::sort(sorted.begin(), sorted.end());
  EXPECT_EQ(std::adjacent_find(sorted.begin(), sorted.end()), sorted.end());
}

}
