#pragma once

#include "qsafe/common/encoding.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace qsafe::crypto {

using Hash = std::array<uint8_t, 32>;

std::optional<Hash> sha256(const common::Bytes& input);
std::optional<Hash> leafHash(std::string_view file_id, uint64_t version, uint64_t index,
                             const common::Bytes& shard);
std::optional<Hash> nodeHash(const Hash& left, const Hash& right);

}
