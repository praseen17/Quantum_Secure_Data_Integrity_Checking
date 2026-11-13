#pragma once

#include "qsafe/common/encoding.hpp"

#include <optional>
#include <string>

namespace qsafe::crypto {

class SigningKeyPair {
 public:
  SigningKeyPair() = default;
  ~SigningKeyPair();
  SigningKeyPair(const SigningKeyPair&) = delete;
  SigningKeyPair& operator=(const SigningKeyPair&) = delete;
  SigningKeyPair(SigningKeyPair&& other) noexcept;
  SigningKeyPair& operator=(SigningKeyPair&& other) noexcept;

  common::Bytes public_key;

 private:
  common::Bytes secret_key_;
  friend class LiboqsSigner;
};

class LiboqsSigner {
 public:
  static std::optional<LiboqsSigner> create(const std::string& algorithm, std::string& error);

  std::optional<SigningKeyPair> generateKeyPair() const;
  std::optional<common::Bytes> sign(const common::Bytes& message,
                                    const SigningKeyPair& key_pair) const;
  bool verify(const common::Bytes& message, const common::Bytes& signature,
              const common::Bytes& public_key) const;
  const std::string& algorithm() const;

 private:
  explicit LiboqsSigner(std::string algorithm);

  std::string algorithm_;
};

}
