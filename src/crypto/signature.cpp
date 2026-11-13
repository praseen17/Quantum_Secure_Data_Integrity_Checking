#include "qsafe/crypto/signature.hpp"

#include <oqs/oqs.h>
#include <openssl/crypto.h>

#include <memory>
#include <utility>

namespace qsafe::crypto {

namespace {

using SignatureContext = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>;

SignatureContext makeContext(const std::string& algorithm) {
  return SignatureContext(OQS_SIG_new(algorithm.c_str()), OQS_SIG_free);
}

const uint8_t* messageData(const common::Bytes& message) {
  static const uint8_t empty_message = 0;
  return message.empty() ? &empty_message : message.data();
}

}

SigningKeyPair::~SigningKeyPair() {
  if (!secret_key_.empty()) OPENSSL_cleanse(secret_key_.data(), secret_key_.size());
}

SigningKeyPair::SigningKeyPair(SigningKeyPair&& other) noexcept
    : public_key(std::move(other.public_key)), secret_key_(std::move(other.secret_key_)) {}

SigningKeyPair& SigningKeyPair::operator=(SigningKeyPair&& other) noexcept {
  if (this == &other) return *this;
  if (!secret_key_.empty()) OPENSSL_cleanse(secret_key_.data(), secret_key_.size());
  public_key = std::move(other.public_key);
  secret_key_ = std::move(other.secret_key_);
  return *this;
}

LiboqsSigner::LiboqsSigner(std::string algorithm) : algorithm_(std::move(algorithm)) {}

std::optional<LiboqsSigner> LiboqsSigner::create(const std::string& algorithm,
                                                  std::string& error) {
  if (algorithm != "ML-DSA-44" && algorithm != "ML-DSA-65") {
    error = "unsupported signature algorithm: " + algorithm;
    return std::nullopt;
  }
  if (OQS_SIG_alg_is_enabled(algorithm.c_str()) != 1) {
    error = "signature algorithm is not enabled in liboqs: " + algorithm;
    return std::nullopt;
  }
  auto context = makeContext(algorithm);
  if (!context) {
    error = "liboqs failed to initialize signature algorithm: " + algorithm;
    return std::nullopt;
  }
  error.clear();
  return LiboqsSigner(algorithm);
}

std::optional<SigningKeyPair> LiboqsSigner::generateKeyPair() const {
  auto context = makeContext(algorithm_);
  if (!context) return std::nullopt;

  SigningKeyPair key_pair;
  key_pair.public_key.resize(context->length_public_key);
  key_pair.secret_key_.resize(context->length_secret_key);
  if (OQS_SIG_keypair(context.get(), key_pair.public_key.data(), key_pair.secret_key_.data()) !=
      OQS_SUCCESS) {
    return std::nullopt;
  }
  return key_pair;
}

std::optional<common::Bytes> LiboqsSigner::sign(const common::Bytes& message,
                                                const SigningKeyPair& key_pair) const {
  auto context = makeContext(algorithm_);
  if (!context || key_pair.secret_key_.size() != context->length_secret_key) {
    return std::nullopt;
  }

  common::Bytes signature(context->length_signature);
  size_t signature_length = 0;
  if (OQS_SIG_sign(context.get(), signature.data(), &signature_length, messageData(message),
                   message.size(), key_pair.secret_key_.data()) != OQS_SUCCESS ||
      signature_length != context->length_signature) {
    return std::nullopt;
  }
  signature.resize(signature_length);
  return signature;
}

bool LiboqsSigner::verify(const common::Bytes& message, const common::Bytes& signature,
                          const common::Bytes& public_key) const {
  auto context = makeContext(algorithm_);
  if (!context || public_key.size() != context->length_public_key ||
      signature.size() != context->length_signature) {
    return false;
  }
  return OQS_SIG_verify(context.get(), messageData(message), message.size(), signature.data(),
                        signature.size(), public_key.data()) == OQS_SUCCESS;
}

const std::string& LiboqsSigner::algorithm() const { return algorithm_; }

}
