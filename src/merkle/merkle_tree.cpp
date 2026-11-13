#include "qsafe/merkle/merkle_tree.hpp"

#include <utility>

namespace qsafe::merkle {

MerkleTree::MerkleTree(std::vector<std::vector<crypto::Hash>> levels)
    : levels_(std::move(levels)) {}

std::optional<MerkleTree> MerkleTree::build(const std::vector<crypto::Hash>& leaves) {
  if (leaves.empty()) return std::nullopt;

  std::vector<std::vector<crypto::Hash>> levels;
  levels.push_back(leaves);
  while (levels.back().size() > 1) {
    const auto& current = levels.back();
    std::vector<crypto::Hash> next;
    next.reserve(current.size() / 2 + current.size() % 2);
    for (size_t i = 0; i < current.size(); i += 2) {
      if (i + 1 == current.size()) {
        next.push_back(current[i]);
        continue;
      }
      const auto parent = crypto::nodeHash(current[i], current[i + 1]);
      if (!parent.has_value()) return std::nullopt;
      next.push_back(*parent);
    }
    levels.push_back(std::move(next));
  }
  return MerkleTree(std::move(levels));
}

bool MerkleTree::verify(const crypto::Hash& leaf, uint64_t index, uint64_t leaf_count,
                        const std::vector<crypto::Hash>& proof, const crypto::Hash& root) {
  if (leaf_count == 0 || index >= leaf_count) return false;

  crypto::Hash current = leaf;
  size_t proof_position = 0;
  uint64_t node_count = leaf_count;
  while (node_count > 1) {
    const bool has_left_sibling = (index % 2) == 1;
    const bool has_right_sibling = !has_left_sibling && index + 1 < node_count;
    if (has_left_sibling || has_right_sibling) {
      if (proof_position >= proof.size()) return false;
      const auto parent = has_left_sibling ? crypto::nodeHash(proof[proof_position], current)
                                           : crypto::nodeHash(current, proof[proof_position]);
      if (!parent.has_value()) return false;
      current = *parent;
      ++proof_position;
    }
    index /= 2;
    node_count = node_count / 2 + node_count % 2;
  }
  return proof_position == proof.size() && current == root;
}

const crypto::Hash& MerkleTree::root() const { return levels_.back().front(); }

std::optional<std::vector<crypto::Hash>> MerkleTree::path(uint64_t index) const {
  if (levels_.empty() || index >= static_cast<uint64_t>(levels_.front().size())) {
    return std::nullopt;
  }

  std::vector<crypto::Hash> proof;
  uint64_t node_index = index;
  uint64_t node_count = static_cast<uint64_t>(levels_.front().size());
  for (size_t level = 0; level + 1 < levels_.size(); ++level) {
    if ((node_index % 2) == 1) {
      proof.push_back(levels_[level][static_cast<size_t>(node_index - 1)]);
    } else if (node_index + 1 < node_count) {
      proof.push_back(levels_[level][static_cast<size_t>(node_index + 1)]);
    }
    node_index /= 2;
    node_count = node_count / 2 + node_count % 2;
  }
  return proof;
}

}
