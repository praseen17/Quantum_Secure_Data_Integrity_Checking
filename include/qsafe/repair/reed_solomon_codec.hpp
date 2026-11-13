#pragma once

#include "qsafe/common/encoding.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace qsafe::repair {

struct IndexedShard {
  uint32_t index = 0;
  common::Bytes bytes;

  bool operator==(const IndexedShard& other) const {
    return index == other.index && bytes == other.bytes;
  }
};

class ReedSolomonCodec {
 public:
  static std::optional<ReedSolomonCodec> create(uint32_t data_shards, uint32_t parity_shards,
                                                std::string& error);

  std::optional<std::vector<common::Bytes>> encodeStripe(
      const std::vector<common::Bytes>& data) const;
  std::optional<std::vector<IndexedShard>> decodeStripe(
      const std::vector<IndexedShard>& available) const;
  uint32_t dataShardCount() const;
  uint32_t parityShardCount() const;

 private:
  ReedSolomonCodec(uint32_t data_shards, uint32_t parity_shards);

  uint32_t data_shards_;
  uint32_t parity_shards_;
};

}
