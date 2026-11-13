#include "qsafe/crypto/hash.hpp"

#include <gtest/gtest.h>

namespace qsafe::crypto {

using common::Bytes;

TEST(Sha256, EmptyInputMatchesKnownAnswer) {
  const auto digest = sha256(common::Bytes{});
  ASSERT_TRUE(digest.has_value());
  const Hash expected = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                         0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                         0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                         0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
  EXPECT_EQ(*digest, expected);
}

TEST(DomainSeparatedHash, SameInputsAreDeterministicAndFieldsAreBound) {
  const Bytes shard = {0x10, 0x20, 0x30};
  const auto base = leafHash("ab", 1, 2, shard);
  ASSERT_TRUE(base.has_value());
  EXPECT_EQ(base, leafHash("ab", 1, 2, shard));
  EXPECT_NE(base, leafHash("a", 1, 2, shard));
  EXPECT_NE(leafHash("ab", 1, 2, Bytes{0x30}), leafHash("a", 1, 2, Bytes{0x62, 0x30}));
  EXPECT_NE(base, leafHash("ab", 2, 2, shard));
  EXPECT_NE(base, leafHash("ab", 1, 3, shard));
  EXPECT_NE(base, leafHash("ab", 1, 2, Bytes{0x10, 0x20, 0x31}));
}

TEST(DomainSeparatedHash, LeafAndNodeDomainsAreDistinct) {
  const Hash left{};
  const Hash right{};
  const auto node = nodeHash(left, right);
  const auto leaf = leafHash("", 0, 0, Bytes{});
  ASSERT_TRUE(node.has_value());
  ASSERT_TRUE(leaf.has_value());
  EXPECT_NE(node, leaf);
}

TEST(DomainSeparatedHash, LeafKnownAnswerIsStable) {
  const auto digest = leafHash("fid", 1, 2, Bytes{0x00, 0xff});
  ASSERT_TRUE(digest.has_value());
  const Hash expected = {0x3a, 0x3b, 0x69, 0x7e, 0x25, 0xbd, 0x67, 0x15,
                         0x54, 0xf6, 0x64, 0x49, 0x23, 0xe0, 0x5f, 0xb6,
                         0x3f, 0xe9, 0x07, 0x82, 0x38, 0x6e, 0xaf, 0xa5,
                         0xa6, 0x57, 0x20, 0x46, 0x99, 0x0e, 0x17, 0xe1};
  EXPECT_EQ(*digest, expected);
}

TEST(DomainSeparatedHash, NodeKnownAnswerIsStable) {
  const Hash zero{};
  const auto digest = nodeHash(zero, zero);
  ASSERT_TRUE(digest.has_value());
  const Hash expected = {0x59, 0xb4, 0xe7, 0xc1, 0xa1, 0x10, 0x63, 0xbc,
                         0xe6, 0x48, 0x21, 0x2a, 0x68, 0x1a, 0x10, 0x85,
                         0x95, 0x37, 0x36, 0x5e, 0x7c, 0xba, 0x7f, 0xce,
                         0xe7, 0xc6, 0x84, 0x25, 0x88, 0x76, 0xe4, 0x35};
  EXPECT_EQ(*digest, expected);
}

}
