#include "qsafe/bench/faults/fault_injector.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <string>

namespace qsafe::bench::faults {

namespace {

class TemporaryStore {
 public:
  TemporaryStore() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    root_ = std::filesystem::temp_directory_path() /
            ("qsafe-fault-test-" + std::to_string(suffix));
  }
  ~TemporaryStore() { std::filesystem::remove_all(root_); }
  const std::filesystem::path& root() const { return root_; }

 private:
  std::filesystem::path root_;
};

}

TEST(FaultInjector, SameSeedProducesSameDamageSetAndRequestedCount) {
  FaultInjector first(77);
  FaultInjector second(77);
  const auto left = first.randomCorruption(100, 0.15);
  const auto right = second.randomCorruption(100, 0.15);
  ASSERT_TRUE(left.has_value());
  ASSERT_TRUE(right.has_value());
  EXPECT_EQ(left->events, right->events);
  EXPECT_EQ(left->events.size(), 15U);
}

TEST(FaultInjector, CreatesClusteredParityAndUnrecoverableSchedules) {
  FaultInjector injector(9);
  const auto cluster = injector.clusteredCorruption(4, 4, 2, 1, 3);
  ASSERT_TRUE(cluster.has_value());
  ASSERT_EQ(cluster->events.size(), 3U);
  for (const auto& event : cluster->events) EXPECT_EQ(event.index / 6, 1U);

  const auto parity = injector.parityCorruption(4, 4, 2, 2, 1);
  ASSERT_TRUE(parity.has_value());
  ASSERT_EQ(parity->events.size(), 1U);
  EXPECT_EQ(parity->events[0].index, 2 * 6 + 4 + 1);

  const auto unrecoverable = injector.beyondRecoverability(1, 4, 2);
  ASSERT_TRUE(unrecoverable.has_value());
  EXPECT_EQ(unrecoverable->events.size(), 3U);
}

TEST(FaultInjector, RepeatsTheSameStripeFailuresAcrossRounds) {
  FaultInjector injector(2);
  const auto rounds = injector.repeatedStripeFailures(5, 4, 2, 3, {0, 5}, 4);
  ASSERT_TRUE(rounds.has_value());
  ASSERT_EQ(rounds->size(), 4U);
  for (const auto& round : *rounds) {
    ASSERT_EQ(round.events.size(), 2U);
    EXPECT_EQ(round.events[0].index, 18U);
    EXPECT_EQ(round.events[1].index, 23U);
  }
}

TEST(FaultInjector, RepresentsStaleManifestReplayAndRejectsInvalidScenarios) {
  FaultInjector injector(3);
  const auto stale = injector.staleManifestReplay(4);
  ASSERT_TRUE(stale.has_value());
  EXPECT_EQ(stale->stale_manifest_version, 4U);
  EXPECT_FALSE(injector.clusteredCorruption(2, 4, 2, 2, 1).has_value());
  EXPECT_FALSE(injector.randomCorruption(10, 1.1).has_value());
}

TEST(FaultInjector, AppliesCorruptionAndDeletionToSimulatedCloud) {
  TemporaryStore temporary;
  std::string error;
  auto cloud = storage::CloudStorage::open(temporary.root(), error);
  ASSERT_TRUE(cloud.has_value()) << error;
  std::vector<common::Bytes> shards = {{1, 2}, {3, 4}};
  std::vector<std::vector<crypto::Hash>> paths(2);
  ASSERT_TRUE(cloud->put("fault-file", 1, shards, paths, error)) << error;

  FaultInjector injector(11);
  FaultSchedule schedule;
  schedule.events = {{0, FaultKind::Corrupt}, {1, FaultKind::Delete}};
  ASSERT_TRUE(injector.apply(*cloud, "fault-file", 1, schedule, error)) << error;
  const auto corrupted = cloud->getShard("fault-file", 1, 0);
  ASSERT_EQ(corrupted.status, storage::ReadStatus::Available);
  EXPECT_NE(corrupted.bytes, shards[0]);
  EXPECT_EQ(cloud->getShard("fault-file", 1, 1).status, storage::ReadStatus::Unavailable);
}

}
