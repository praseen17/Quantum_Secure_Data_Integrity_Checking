#include "qsafe/common/encoding.hpp"
#include "qsafe/crypto/hash.hpp"
#include "qsafe/merkle/merkle_tree.hpp"

#include <gtest/gtest.h>

namespace qsafe::merkle {

TEST(MerkleIntegration, CanonicalFieldsHashAndProofVerifyEndToEnd) {
  common::CanonicalWriter writer;
  ASSERT_TRUE(writer.writeString("report-17"));
  ASSERT_TRUE(writer.writeU64(4));
  ASSERT_TRUE(writer.writeU64(0));
  ASSERT_TRUE(writer.writeBytes(common::Bytes{0x10, 0x20, 0x30}));

  common::CanonicalReader reader(writer.data());
  std::string file_id;
  uint64_t version = 0;
  uint64_t index = 0;
  common::Bytes shard;
  ASSERT_TRUE(reader.readString(file_id, 64));
  ASSERT_TRUE(reader.readU64(version));
  ASSERT_TRUE(reader.readU64(index));
  ASSERT_TRUE(reader.readBytes(shard, 1024));
  ASSERT_TRUE(reader.finished());

  const auto first = crypto::leafHash(file_id, version, index, shard);
  const auto second = crypto::leafHash(file_id, version, index + 1, common::Bytes{0x40});
  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  const auto tree = MerkleTree::build({*first, *second});
  ASSERT_TRUE(tree.has_value());
  const auto proof = tree->path(index);
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(MerkleTree::verify(*first, index, 2, *proof, tree->root()));
}

}
