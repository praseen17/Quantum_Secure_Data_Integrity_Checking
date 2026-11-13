#include "qsafe/storage/chunker.hpp"

#include <algorithm>
#include <limits>

namespace qsafe::storage {

std::optional<ChunkedFile> FileChunker::split(const common::Bytes& input, size_t shard_size) {
  constexpr size_t kMaximumShardSize = 64 * 1024 * 1024;
  if (shard_size == 0 || shard_size > kMaximumShardSize) return std::nullopt;

  ChunkedFile output;
  output.original_length = input.size();
  output.shard_size = shard_size;
  const size_t count = input.size() / shard_size + (input.size() % shard_size != 0);
  output.shards.reserve(count);
  for (size_t offset = 0; offset < input.size();) {
    common::Bytes shard(shard_size, 0);
    const size_t remaining = input.size() - offset;
    const size_t copy_size = std::min(remaining, shard_size);
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(offset), copy_size, shard.begin());
    output.shards.push_back(std::move(shard));
    offset += copy_size;
  }
  return output;
}

std::optional<common::Bytes> FileChunker::reassemble(const ChunkedFile& file) {
  constexpr size_t kMaximumShardSize = 64 * 1024 * 1024;
  if (file.shard_size == 0 || file.shard_size > kMaximumShardSize ||
      file.original_length > std::numeric_limits<size_t>::max()) {
    return std::nullopt;
  }
  const uint64_t expected_count = file.original_length / file.shard_size +
                                  (file.original_length % file.shard_size != 0);
  if (expected_count != file.shards.size()) return std::nullopt;
  for (const auto& shard : file.shards) {
    if (shard.size() != file.shard_size) return std::nullopt;
  }

  common::Bytes output;
  output.reserve(static_cast<size_t>(file.original_length));
  for (const auto& shard : file.shards) output.insert(output.end(), shard.begin(), shard.end());
  output.resize(static_cast<size_t>(file.original_length));
  return output;
}

}
