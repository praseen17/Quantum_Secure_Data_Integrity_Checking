#pragma once

#include "qsafe/crypto/hash.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace qsafe::merkle {

class MerkleTree {
 public:
  static std::optional<MerkleTree> build(const std::vector<crypto::Hash>& leaves);
  static bool verify(const crypto::Hash& leaf, uint64_t index, uint64_t leaf_count,
                     const std::vector<crypto::Hash>& proof, const crypto::Hash& root);

  const crypto::Hash& root() const;
  std::optional<std::vector<crypto::Hash>> path(uint64_t index) const;

 private:
  explicit MerkleTree(std::vector<std::vector<crypto::Hash>> levels);

  std::vector<std::vector<crypto::Hash>> levels_;
};

}
