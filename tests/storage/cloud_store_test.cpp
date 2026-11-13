#include "qsafe/storage/cloud_store.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <string>

namespace qsafe::storage {

namespace {

class TemporaryStore {
 public:
  TemporaryStore() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    root_ = std::filesystem::temp_directory_path() /
            ("qsafe-cloud-test-" + std::to_string(suffix));
  }
  ~TemporaryStore() { std::filesystem::remove_all(root_); }
  const std::filesystem::path& root() const { return root_; }

 private:
  std::filesystem::path root_;
};

std::vector<crypto::Hash> makePaths(size_t count) {
  std::vector<crypto::Hash> paths(count);
  for (size_t i = 0; i < count; ++i) paths[i][0] = static_cast<uint8_t>(i + 1);
  return paths;
}

}

TEST(CloudStore, StoresAndRetrievesVersionedShardsAndProofs) {
  TemporaryStore temporary;
  std::string error;
  auto store = CloudStorage::open(temporary.root(), error);
  ASSERT_TRUE(store.has_value()) << error;
  const std::vector<common::Bytes> shards = {{1, 2, 3}, {4, 5, 6}};
  const std::vector<std::vector<crypto::Hash>> proofs = {makePaths(2), makePaths(1)};
  ASSERT_TRUE(store->put("file-1", 2, shards, proofs, error)) << error;
  EXPECT_FALSE(store->put("file-1", 2, {{9, 9, 9}}, {makePaths(1)}, error));

  const auto shard = store->getShard("file-1", 2, 1);
  ASSERT_EQ(shard.status, ReadStatus::Available);
  EXPECT_EQ(shard.bytes, shards[1]);
  const auto proof = store->getPath("file-1", 2, 0);
  ASSERT_TRUE(proof.has_value());
  EXPECT_EQ(*proof, proofs[0]);
  EXPECT_TRUE(std::filesystem::exists(temporary.root() / "metadata.sqlite"));
}

TEST(CloudStore, MissingOrMarkedUnavailableShardReturnsUnavailable) {
  TemporaryStore temporary;
  std::string error;
  auto store = CloudStorage::open(temporary.root(), error);
  ASSERT_TRUE(store.has_value()) << error;
  EXPECT_EQ(store->getShard("missing", 1, 0).status, ReadStatus::Unavailable);

  ASSERT_TRUE(store->put("file", 1, {{1, 2}}, {makePaths(1)}, error)) << error;
  ASSERT_TRUE(store->setAvailability("file", 1, 0, ShardAvailability::Unavailable, error))
      << error;
  EXPECT_EQ(store->getShard("file", 1, 0).status, ReadStatus::Unavailable);
  EXPECT_TRUE(store->getPath("file", 1, 0).has_value());
}

TEST(CloudStore, RejectsInvalidFileIdsAndMismatchedInputs) {
  TemporaryStore temporary;
  std::string error;
  auto store = CloudStorage::open(temporary.root(), error);
  ASSERT_TRUE(store.has_value()) << error;
  EXPECT_FALSE(store->put(std::string("\xff", 1), 1, {{1}}, {makePaths(1)}, error));
  EXPECT_FALSE(store->put("file", 0, {{1}}, {makePaths(1)}, error));
  EXPECT_FALSE(store->put("file", 1, {{1}}, {}, error));
}

}
