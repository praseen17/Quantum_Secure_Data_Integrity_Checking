#include "qsafe/repair/reed_solomon_codec.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace qsafe::repair {

namespace {

std::vector<common::Bytes> dataShards(uint32_t count, size_t size) {
  std::vector<common::Bytes> data(count, common::Bytes(size));
  for (uint32_t shard = 0; shard < count; ++shard) {
    for (size_t byte = 0; byte < size; ++byte) {
      data[shard][byte] = static_cast<uint8_t>((shard * 31 + byte * 17 + 3) % 256);
    }
  }
  return data;
}

std::vector<IndexedShard> fullStripe(const std::vector<common::Bytes>& data,
                                    const std::vector<common::Bytes>& parity) {
  std::vector<IndexedShard> shards;
  for (size_t i = 0; i < data.size(); ++i) {
    shards.push_back({static_cast<uint32_t>(i), data[i]});
  }
  for (size_t i = 0; i < parity.size(); ++i) {
    shards.push_back({static_cast<uint32_t>(data.size() + i), parity[i]});
  }
  return shards;
}

std::vector<IndexedShard> without(const std::vector<IndexedShard>& stripe,
                                  const std::vector<uint32_t>& missing) {
  std::vector<IndexedShard> available;
  for (const auto& shard : stripe) {
    if (std::find(missing.begin(), missing.end(), shard.index) == missing.end()) {
      available.push_back(shard);
    }
  }
  return available;
}

std::vector<IndexedShard> merge(const std::vector<IndexedShard>& available,
                                const std::vector<IndexedShard>& recovered) {
  auto result = available;
  result.insert(result.end(), recovered.begin(), recovered.end());
  std::sort(result.begin(), result.end(),
            [](const IndexedShard& left, const IndexedShard& right) {
              return left.index < right.index;
            });
  return result;
}

}

TEST(ReedSolomonCodec, RecoversEverySingleAndDoubleErasureForFourPlusTwo) {
  std::string error;
  const auto codec = ReedSolomonCodec::create(4, 2, error);
  ASSERT_TRUE(codec.has_value()) << error;
  const auto data = dataShards(4, 257);
  const auto parity = codec->encodeStripe(data);
  ASSERT_TRUE(parity.has_value());
  const auto stripe = fullStripe(data, *parity);

  for (uint32_t first = 0; first < 6; ++first) {
    const auto recovered = codec->decodeStripe(without(stripe, {first}));
    ASSERT_TRUE(recovered.has_value()) << "missing=" << first;
    EXPECT_EQ(merge(without(stripe, {first}), *recovered), stripe);
  }
  for (uint32_t first = 0; first < 6; ++first) {
    for (uint32_t second = first + 1; second < 6; ++second) {
      const auto available = without(stripe, {first, second});
      const auto recovered = codec->decodeStripe(available);
      ASSERT_TRUE(recovered.has_value()) << "missing=" << first << ',' << second;
      EXPECT_EQ(merge(available, *recovered), stripe);
    }
  }
}

TEST(ReedSolomonCodec, ReportsThreeErasureFailureForFourPlusTwo) {
  std::string error;
  const auto codec = ReedSolomonCodec::create(4, 2, error);
  ASSERT_TRUE(codec.has_value()) << error;
  const auto data = dataShards(4, 100);
  const auto parity = codec->encodeStripe(data);
  ASSERT_TRUE(parity.has_value());
  const auto stripe = fullStripe(data, *parity);
  EXPECT_FALSE(codec->decodeStripe(without(stripe, {0, 2, 5})).has_value());
}

TEST(ReedSolomonCodec, ParityOnlyLossAndSixPlusThreeDecodeCorrectly) {
  std::string error;
  const auto codec = ReedSolomonCodec::create(4, 2, error);
  ASSERT_TRUE(codec.has_value()) << error;
  const auto data = dataShards(4, 4096);
  const auto parity = codec->encodeStripe(data);
  ASSERT_TRUE(parity.has_value());
  const auto stripe = fullStripe(data, *parity);
  const auto available = without(stripe, {4, 5});
  const auto recovered = codec->decodeStripe(available);
  ASSERT_TRUE(recovered.has_value());
  EXPECT_EQ(merge(available, *recovered), stripe);

  const auto larger_codec = ReedSolomonCodec::create(6, 3, error);
  ASSERT_TRUE(larger_codec.has_value()) << error;
  const auto larger_data = dataShards(6, 513);
  const auto larger_parity = larger_codec->encodeStripe(larger_data);
  ASSERT_TRUE(larger_parity.has_value());
  const auto larger_stripe = fullStripe(larger_data, *larger_parity);
  const auto larger_available = without(larger_stripe, {0, 4, 8});
  const auto larger_recovered = larger_codec->decodeStripe(larger_available);
  ASSERT_TRUE(larger_recovered.has_value());
  EXPECT_EQ(merge(larger_available, *larger_recovered), larger_stripe);
}

TEST(ReedSolomonCodec, RejectsInvalidConfigurationsAndInputs) {
  std::string error;
  EXPECT_FALSE(ReedSolomonCodec::create(0, 2, error).has_value());
  EXPECT_FALSE(ReedSolomonCodec::create(4, 22, error).has_value());
  const auto codec = ReedSolomonCodec::create(4, 2, error);
  ASSERT_TRUE(codec.has_value());
  EXPECT_FALSE(codec->encodeStripe(dataShards(3, 32)).has_value());
  EXPECT_FALSE(codec->encodeStripe(dataShards(4, 0)).has_value());
  EXPECT_FALSE(codec->decodeStripe({}).has_value());

  const std::vector<IndexedShard> duplicate = {{0, common::Bytes(32)},
                                                 {0, common::Bytes(32)},
                                                 {1, common::Bytes(32)},
                                                 {2, common::Bytes(32)}};
  EXPECT_FALSE(codec->decodeStripe(duplicate).has_value());
}

}
