#include "qsafe/merkle/merkle_tree.hpp"

#include <gtest/gtest.h>

#include <array>
#include <vector>

namespace qsafe::merkle {

namespace {

std::vector<crypto::Hash> makeLeaves(size_t count, uint8_t offset = 0) {
  std::vector<crypto::Hash> leaves(count);
  for (size_t i = 0; i < count; ++i) {
    leaves[i][0] = static_cast<uint8_t>(i + offset);
    leaves[i][1] = static_cast<uint8_t>((i * 7) + offset);
  }
  return leaves;
}

}

TEST(MerkleTree, BuildsAndVerifiesEveryIndexForOddAndEvenSizes) {
  for (const size_t count : {1U, 2U, 3U, 5U, 8U, 100U}) {
    const auto leaves = makeLeaves(count);
    const auto tree = MerkleTree::build(leaves);
    ASSERT_TRUE(tree.has_value()) << "leaf count=" << count;
    for (size_t index = 0; index < count; ++index) {
      const auto proof = tree->path(index);
      ASSERT_TRUE(proof.has_value()) << "index=" << index;
      EXPECT_TRUE(MerkleTree::verify(leaves[index], index, count, *proof, tree->root()))
          << "leaf count=" << count << " index=" << index;
    }
  }
}

TEST(MerkleTree, RejectsEmptyTreesAndInvalidIndices) {
  EXPECT_FALSE(MerkleTree::build({}).has_value());
  const auto leaves = makeLeaves(3);
  const auto tree = MerkleTree::build(leaves);
  ASSERT_TRUE(tree.has_value());
  EXPECT_FALSE(tree->path(3).has_value());
  EXPECT_FALSE(MerkleTree::verify(leaves[0], 3, leaves.size(), {}, tree->root()));
}

TEST(MerkleTree, RejectsWrongIndexAndForeignLeaf) {
  const auto leaves = makeLeaves(5);
  const auto other_leaves = makeLeaves(5, 90);
  const auto tree = MerkleTree::build(leaves);
  ASSERT_TRUE(tree.has_value());
  const auto proof = tree->path(1);
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(MerkleTree::verify(leaves[1], 2, leaves.size(), *proof, tree->root()));
  EXPECT_FALSE(MerkleTree::verify(other_leaves[1], 1, leaves.size(), *proof, tree->root()));
}

TEST(MerkleTree, RejectsReorderedTruncatedAndExtendedProofs) {
  const auto leaves = makeLeaves(8);
  const auto tree = MerkleTree::build(leaves);
  ASSERT_TRUE(tree.has_value());
  auto proof = tree->path(3);
  ASSERT_TRUE(proof.has_value());
  ASSERT_GE(proof->size(), 2U);

  auto reordered = *proof;
  std::swap(reordered[0], reordered[1]);
  EXPECT_FALSE(MerkleTree::verify(leaves[3], 3, leaves.size(), reordered, tree->root()));

  auto truncated = *proof;
  truncated.pop_back();
  EXPECT_FALSE(MerkleTree::verify(leaves[3], 3, leaves.size(), truncated, tree->root()));

  auto extended = *proof;
  extended.push_back(crypto::Hash{});
  EXPECT_FALSE(MerkleTree::verify(leaves[3], 3, leaves.size(), extended, tree->root()));
}

TEST(MerkleTree, PromotesUnpairedOddNodeWithoutAddingDuplicateSibling) {
  const auto leaves = makeLeaves(3);
  const auto tree = MerkleTree::build(leaves);
  ASSERT_TRUE(tree.has_value());
  const auto proof = tree->path(2);
  ASSERT_TRUE(proof.has_value());
  ASSERT_EQ(proof->size(), 1U);
  EXPECT_EQ((*proof)[0], *crypto::nodeHash(leaves[0], leaves[1]));
  EXPECT_TRUE(MerkleTree::verify(leaves[2], 2, 3, *proof, tree->root()));
}

TEST(MerkleTree, InternalNodeCannotBePresentedAsLeaf) {
  const auto leaves = makeLeaves(4);
  const auto tree = MerkleTree::build(leaves);
  ASSERT_TRUE(tree.has_value());
  const auto proof = tree->path(0);
  ASSERT_TRUE(proof.has_value());
  const auto internal = crypto::nodeHash(leaves[0], leaves[1]);
  ASSERT_TRUE(internal.has_value());
  EXPECT_FALSE(MerkleTree::verify(*internal, 0, leaves.size(), *proof, tree->root()));
}

}
