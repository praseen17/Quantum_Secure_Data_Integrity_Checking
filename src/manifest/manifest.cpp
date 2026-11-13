#include "qsafe/manifest/manifest.hpp"

#include <algorithm>
#include <limits>

namespace qsafe::manifest {

namespace {

constexpr size_t kMaxFileIdSize = 1024;
constexpr size_t kMaxCodecSize = 64;
constexpr size_t kMaxHashIdSize = 64;

bool valid(const Manifest& manifest) {
  return !manifest.file_id.empty() && manifest.file_id.size() <= kMaxFileIdSize &&
         manifest.version > 0 && manifest.shard_count > 0 && manifest.data_shards > 0 &&
         manifest.parity_shards > 0 &&
         static_cast<uint64_t>(manifest.data_shards) + manifest.parity_shards <=
             manifest.shard_count &&
         manifest.shard_count %
                 (static_cast<uint64_t>(manifest.data_shards) + manifest.parity_shards) ==
             0 &&
         !manifest.codec.empty() && manifest.codec.size() <= kMaxCodecSize &&
         !manifest.hash_id.empty() && manifest.hash_id.size() <= kMaxHashIdSize &&
         manifest.protocol_version > 0;
}

}

bool Manifest::operator==(const Manifest& other) const {
  return file_id == other.file_id && version == other.version && root == other.root &&
         shard_count == other.shard_count && data_shards == other.data_shards &&
         parity_shards == other.parity_shards && codec == other.codec &&
         hash_id == other.hash_id && protocol_version == other.protocol_version;
}

std::optional<common::Bytes> serialize(const Manifest& manifest) {
  if (!valid(manifest)) return std::nullopt;
  common::CanonicalWriter writer;
  if (!writer.writeString(manifest.file_id) || !writer.writeU64(manifest.version) ||
      !writer.writeBytes(manifest.root.data(), manifest.root.size()) ||
      !writer.writeU64(manifest.shard_count) || !writer.writeU32(manifest.data_shards) ||
      !writer.writeU32(manifest.parity_shards) || !writer.writeString(manifest.codec) ||
      !writer.writeString(manifest.hash_id) || !writer.writeU32(manifest.protocol_version) ||
      !writer.valid()) {
    return std::nullopt;
  }
  return writer.data();
}

std::optional<Manifest> deserialize(const common::Bytes& encoded) {
  common::CanonicalReader reader(encoded);
  Manifest manifest;
  common::Bytes root;
  if (!reader.readString(manifest.file_id, kMaxFileIdSize) ||
      !reader.readU64(manifest.version) || !reader.readBytes(root, crypto::Hash{}.size()) ||
      root.size() != crypto::Hash{}.size() || !reader.readU64(manifest.shard_count) ||
      !reader.readU32(manifest.data_shards) || !reader.readU32(manifest.parity_shards) ||
      !reader.readString(manifest.codec, kMaxCodecSize) ||
      !reader.readString(manifest.hash_id, kMaxHashIdSize) ||
      !reader.readU32(manifest.protocol_version) || !reader.finished() || !valid(manifest)) {
    return std::nullopt;
  }
  std::copy(root.begin(), root.end(), manifest.root.begin());
  return manifest;
}

std::optional<common::Bytes> sign(const Manifest& manifest, const crypto::LiboqsSigner& signer,
                                  const crypto::SigningKeyPair& owner_key_pair) {
  const auto encoded = serialize(manifest);
  if (!encoded.has_value()) return std::nullopt;
  return signer.sign(*encoded, owner_key_pair);
}

bool verify(const Manifest& manifest, const common::Bytes& signature,
            const crypto::LiboqsSigner& signer, const common::Bytes& trusted_owner_public_key) {
  const auto encoded = serialize(manifest);
  return encoded.has_value() && signer.verify(*encoded, signature, trusted_owner_public_key);
}

}
