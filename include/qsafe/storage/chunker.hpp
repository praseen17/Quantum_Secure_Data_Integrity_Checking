#pragma once

#include "qsafe/common/encoding.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace qsafe::storage {

struct ChunkedFile {
  uint64_t original_length = 0;
  size_t shard_size = 0;
  std::vector<common::Bytes> shards;
};

class FileChunker {
 public:
  static constexpr size_t kDefaultShardSize = 64 * 1024;
  static std::optional<ChunkedFile> split(const common::Bytes& input,
                                          size_t shard_size = kDefaultShardSize);
  static std::optional<common::Bytes> reassemble(const ChunkedFile& file);
};

}
