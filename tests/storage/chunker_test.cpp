#include "qsafe/storage/chunker.hpp"

#include <gtest/gtest.h>

namespace qsafe::storage {

TEST(Chunker, RoundTripsEmptyAndBoundarySizedFiles) {
  constexpr size_t shard_size = 4096;
  const std::vector<size_t> sizes = {0, 1, shard_size - 1, shard_size, shard_size + 1,
                                     10 * 1024 * 1024};
  for (const size_t size : sizes) {
    common::Bytes input(size);
    for (size_t i = 0; i < input.size(); ++i) input[i] = static_cast<uint8_t>(i % 251);
    const auto chunks = FileChunker::split(input, shard_size);
    ASSERT_TRUE(chunks.has_value()) << "size=" << size;
    EXPECT_EQ(chunks->original_length, size);
    for (const auto& chunk : chunks->shards) EXPECT_EQ(chunk.size(), shard_size);
    const auto output = FileChunker::reassemble(*chunks);
    ASSERT_TRUE(output.has_value()) << "size=" << size;
    EXPECT_EQ(*output, input);
  }
}

TEST(Chunker, RejectsInvalidShardSizeAndInconsistentChunks) {
  EXPECT_FALSE(FileChunker::split(common::Bytes{1}, 0).has_value());
  ChunkedFile invalid;
  invalid.original_length = 1;
  invalid.shard_size = 4;
  invalid.shards = {common::Bytes{1, 2, 3}};
  EXPECT_FALSE(FileChunker::reassemble(invalid).has_value());
}

}
