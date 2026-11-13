#pragma once

#include "qsafe/crypto/hash.hpp"
#include "qsafe/crypto/signature.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace qsafe::manifest {

struct Manifest {
  std::string file_id;
  uint64_t version = 0;
  crypto::Hash root{};
  uint64_t shard_count = 0;
  uint32_t data_shards = 0;
  uint32_t parity_shards = 0;
  std::string codec;
  std::string hash_id;
  uint32_t protocol_version = 0;

  bool operator==(const Manifest& other) const;
};

std::optional<common::Bytes> serialize(const Manifest& manifest);
std::optional<Manifest> deserialize(const common::Bytes& encoded);
std::optional<common::Bytes> sign(const Manifest& manifest, const crypto::LiboqsSigner& signer,
                                 const crypto::SigningKeyPair& owner_key_pair);
bool verify(const Manifest& manifest, const common::Bytes& signature,
            const crypto::LiboqsSigner& signer, const common::Bytes& trusted_owner_public_key);

}
