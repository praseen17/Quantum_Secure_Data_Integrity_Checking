#include "qsafe/common/encoding.hpp"

#include <gtest/gtest.h>

#include <array>

namespace qsafe::common {

TEST(CanonicalEncoding, WritesAndReadsFixedWidthBigEndianFields) {
  CanonicalWriter writer;
  ASSERT_TRUE(writer.writeU8(7));
  ASSERT_TRUE(writer.writeU32(0x01020304));
  ASSERT_TRUE(writer.writeU64(0x0102030405060708ULL));
  ASSERT_TRUE(writer.writeBytes(Bytes{0xaa, 0xbb}));
  ASSERT_TRUE(writer.writeString("x"));

  const Bytes expected = {7, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                          0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x02, 0xaa,
                          0xbb, 0x00, 0x00, 0x00, 0x01, 'x'};
  EXPECT_EQ(writer.data(), expected);

  CanonicalReader reader(writer.data());
  uint8_t u8 = 0;
  uint32_t u32 = 0;
  uint64_t u64 = 0;
  Bytes bytes;
  std::string string;
  ASSERT_TRUE(reader.readU8(u8));
  ASSERT_TRUE(reader.readU32(u32));
  ASSERT_TRUE(reader.readU64(u64));
  ASSERT_TRUE(reader.readBytes(bytes, 2));
  ASSERT_TRUE(reader.readString(string, 1));
  EXPECT_EQ(u8, 7);
  EXPECT_EQ(u32, 0x01020304);
  EXPECT_EQ(u64, 0x0102030405060708ULL);
  EXPECT_EQ(bytes, (Bytes{0xaa, 0xbb}));
  EXPECT_EQ(string, "x");
  EXPECT_TRUE(reader.finished());
}

TEST(CanonicalEncoding, RejectsTruncatedAndOversizedFieldsWithoutAdvancing) {
  CanonicalReader truncated(Bytes{0x00, 0x00, 0x00, 0x02, 0xaa});
  Bytes output;
  EXPECT_FALSE(truncated.readBytes(output, 2));
  EXPECT_EQ(truncated.position(), 0U);

  CanonicalReader oversized(Bytes{0x00, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc});
  EXPECT_FALSE(oversized.readBytes(output, 2));
  EXPECT_EQ(oversized.position(), 0U);

  CanonicalReader short_integer(Bytes{0x01, 0x02, 0x03});
  uint32_t value = 0;
  EXPECT_FALSE(short_integer.readU32(value));
  EXPECT_EQ(short_integer.position(), 0U);
}

TEST(CanonicalEncoding, RejectsMalformedUtf8) {
  CanonicalWriter writer;
  const std::string invalid = std::string("\xc0\x80", 2);
  EXPECT_FALSE(writer.writeString(invalid));
  EXPECT_FALSE(writer.valid());

  CanonicalReader reader(Bytes{0x00, 0x00, 0x00, 0x02, 0xc0, 0x80});
  std::string decoded;
  EXPECT_FALSE(reader.readString(decoded, 2));
  EXPECT_EQ(reader.position(), 0U);
}

TEST(CanonicalEncoding, RejectsTrailingBytesWhenFinishedIsRequired) {
  CanonicalReader reader(Bytes{0x2a, 0x00});
  uint8_t value = 0;
  ASSERT_TRUE(reader.readU8(value));
  EXPECT_FALSE(reader.finished());
}

}
