#include "qsafe/repair/reed_solomon_codec.hpp"

#include <erasure_code.h>

#include <algorithm>
#include <climits>
#include <limits>
#include <set>

namespace qsafe::repair {

namespace {

constexpr size_t kMaximumShardSize = 64 * 1024 * 1024;

bool supportedConfiguration(uint32_t data_shards, uint32_t parity_shards) {
  const uint64_t total = static_cast<uint64_t>(data_shards) + parity_shards;
  if (data_shards == 0 || parity_shards == 0 || total > 255) return false;
  return data_shards <= 3 || (data_shards == 4 && total <= 25) ||
         (data_shards == 5 && total <= 10) || (data_shards <= 21 && parity_shards == 4) ||
         parity_shards <= 3;
}

std::vector<unsigned char> generatorMatrix(uint32_t data_shards, uint32_t parity_shards) {
  const uint32_t total = data_shards + parity_shards;
  std::vector<unsigned char> matrix(static_cast<size_t>(total) * data_shards);
  gf_gen_rs_matrix(matrix.data(), static_cast<int>(total), static_cast<int>(data_shards));
  return matrix;
}

}

ReedSolomonCodec::ReedSolomonCodec(uint32_t data_shards, uint32_t parity_shards)
    : data_shards_(data_shards), parity_shards_(parity_shards) {}

std::optional<ReedSolomonCodec> ReedSolomonCodec::create(uint32_t data_shards,
                                                         uint32_t parity_shards,
                                                         std::string& error) {
  if (!supportedConfiguration(data_shards, parity_shards)) {
    error = "unsupported ISA-L Reed-Solomon configuration";
    return std::nullopt;
  }
  error.clear();
  return ReedSolomonCodec(data_shards, parity_shards);
}

std::optional<std::vector<common::Bytes>> ReedSolomonCodec::encodeStripe(
    const std::vector<common::Bytes>& data) const {
  if (data.size() != data_shards_ || data.empty() || data.front().empty() ||
      data.front().size() > kMaximumShardSize || data.front().size() > INT_MAX) {
    return std::nullopt;
  }
  const size_t shard_size = data.front().size();
  for (const auto& shard : data) {
    if (shard.size() != shard_size) return std::nullopt;
  }

  const auto matrix = generatorMatrix(data_shards_, parity_shards_);
  const size_t coefficient_offset = static_cast<size_t>(data_shards_) * data_shards_;
  const size_t coefficient_size = static_cast<size_t>(parity_shards_) * data_shards_;
  std::vector<unsigned char> coefficients(matrix.begin() + coefficient_offset,
                                           matrix.begin() + coefficient_offset + coefficient_size);
  std::vector<unsigned char> tables(32 * coefficient_size);
  ec_init_tables(static_cast<int>(data_shards_), static_cast<int>(parity_shards_),
                 coefficients.data(), tables.data());

  std::vector<unsigned char*> sources;
  for (const auto& shard : data) {
    sources.push_back(const_cast<unsigned char*>(shard.data()));
  }
  std::vector<common::Bytes> parity(parity_shards_, common::Bytes(shard_size));
  std::vector<unsigned char*> outputs;
  for (auto& shard : parity) outputs.push_back(shard.data());
  ec_encode_data(static_cast<int>(shard_size), static_cast<int>(data_shards_),
                 static_cast<int>(parity_shards_), tables.data(), sources.data(), outputs.data());
  return parity;
}

std::optional<std::vector<IndexedShard>> ReedSolomonCodec::decodeStripe(
    const std::vector<IndexedShard>& available) const {
  const uint32_t total = data_shards_ + parity_shards_;
  if (available.size() < data_shards_ || available.size() > total || available.empty() ||
      available.front().bytes.empty() || available.front().bytes.size() > kMaximumShardSize ||
      available.front().bytes.size() > INT_MAX) {
    return std::nullopt;
  }
  const size_t shard_size = available.front().bytes.size();
  std::set<uint32_t> indices;
  for (const auto& shard : available) {
    if (shard.index >= total || shard.bytes.size() != shard_size ||
        !indices.insert(shard.index).second) {
      return std::nullopt;
    }
  }

  const auto full_matrix = generatorMatrix(data_shards_, parity_shards_);
  const size_t matrix_size = static_cast<size_t>(data_shards_) * data_shards_;
  std::vector<unsigned char> decode_matrix(matrix_size);
  std::vector<unsigned char*> sources;
  for (uint32_t row = 0; row < data_shards_; ++row) {
    const auto& shard = available[row];
    const size_t offset = static_cast<size_t>(shard.index) * data_shards_;
    std::copy_n(full_matrix.begin() + static_cast<std::ptrdiff_t>(offset), data_shards_,
                decode_matrix.begin() + static_cast<std::ptrdiff_t>(row * data_shards_));
    sources.push_back(const_cast<unsigned char*>(shard.bytes.data()));
  }
  std::vector<unsigned char> inverse(matrix_size);
  if (gf_invert_matrix(decode_matrix.data(), inverse.data(), static_cast<int>(data_shards_)) != 0) {
    return std::nullopt;
  }

  const size_t table_size = 32 * matrix_size;
  std::vector<unsigned char> decode_tables(table_size);
  ec_init_tables(static_cast<int>(data_shards_), static_cast<int>(data_shards_), inverse.data(),
                 decode_tables.data());
  std::vector<common::Bytes> data(data_shards_, common::Bytes(shard_size));
  std::vector<unsigned char*> data_outputs;
  for (auto& shard : data) data_outputs.push_back(shard.data());
  ec_encode_data(static_cast<int>(shard_size), static_cast<int>(data_shards_),
                 static_cast<int>(data_shards_), decode_tables.data(), sources.data(),
                 data_outputs.data());

  std::vector<IndexedShard> missing;
  for (uint32_t index = 0; index < total; ++index) {
    if (indices.find(index) != indices.end() || index >= data_shards_) continue;
    missing.push_back({index, data[index]});
  }

  std::vector<uint32_t> missing_parity_indices;
  for (uint32_t index = data_shards_; index < total; ++index) {
    if (indices.find(index) == indices.end()) missing_parity_indices.push_back(index);
  }
  if (!missing_parity_indices.empty()) {
    std::vector<unsigned char> coefficients;
    coefficients.reserve(missing_parity_indices.size() * data_shards_);
    for (const uint32_t index : missing_parity_indices) {
      const size_t offset = static_cast<size_t>(index) * data_shards_;
      coefficients.insert(coefficients.end(), full_matrix.begin() + static_cast<std::ptrdiff_t>(offset),
                          full_matrix.begin() + static_cast<std::ptrdiff_t>(offset + data_shards_));
    }
    const size_t parity_table_size = 32 * coefficients.size();
    std::vector<unsigned char> parity_tables(parity_table_size);
    ec_init_tables(static_cast<int>(data_shards_), static_cast<int>(missing_parity_indices.size()),
                   coefficients.data(), parity_tables.data());
    std::vector<common::Bytes> parity(missing_parity_indices.size(), common::Bytes(shard_size));
    std::vector<unsigned char*> parity_outputs;
    for (auto& shard : parity) parity_outputs.push_back(shard.data());
    ec_encode_data(static_cast<int>(shard_size), static_cast<int>(data_shards_),
                   static_cast<int>(missing_parity_indices.size()), parity_tables.data(),
                   data_outputs.data(), parity_outputs.data());
    for (size_t i = 0; i < parity.size(); ++i) {
      missing.push_back({missing_parity_indices[i], std::move(parity[i])});
    }
  }
  std::sort(missing.begin(), missing.end(),
            [](const IndexedShard& left, const IndexedShard& right) {
              return left.index < right.index;
            });
  return missing;
}

uint32_t ReedSolomonCodec::dataShardCount() const { return data_shards_; }

uint32_t ReedSolomonCodec::parityShardCount() const { return parity_shards_; }

}
