#include "qsafe/crypto/hash.hpp"

#include <openssl/evp.h>

#include <memory>

namespace qsafe::crypto {

std::optional<Hash> sha256(const common::Bytes& input) {
  using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
  Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
    return std::nullopt;
  }
  if (!input.empty() && EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1) {
    return std::nullopt;
  }
  Hash output{};
  unsigned int output_size = 0;
  if (EVP_DigestFinal_ex(context.get(), output.data(), &output_size) != 1 ||
      output_size != output.size()) {
    return std::nullopt;
  }
  return output;
}

std::optional<Hash> leafHash(std::string_view file_id, uint64_t version, uint64_t index,
                             const common::Bytes& shard) {
  common::CanonicalWriter writer;
  if (!writer.writeString("LEAF") || !writer.writeString(file_id) || !writer.writeU64(version) ||
      !writer.writeU64(index) || !writer.writeBytes(shard)) {
    return std::nullopt;
  }
  return sha256(writer.data());
}

std::optional<Hash> nodeHash(const Hash& left, const Hash& right) {
  common::CanonicalWriter writer;
  if (!writer.writeString("NODE") || !writer.writeBytes(left.data(), left.size()) ||
      !writer.writeBytes(right.data(), right.size())) {
    return std::nullopt;
  }
  return sha256(writer.data());
}

}
