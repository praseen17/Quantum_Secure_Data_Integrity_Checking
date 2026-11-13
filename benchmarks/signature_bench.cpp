#include "qsafe/crypto/signature.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <string>

namespace {

using Clock = std::chrono::steady_clock;

double milliseconds(Clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

bool benchmark(const std::string& algorithm, size_t repetitions) {
  std::string error;
  auto signer_value = qsafe::crypto::LiboqsSigner::create(algorithm, error);
  if (!signer_value.has_value()) {
    std::cerr << error << '\n';
    return false;
  }
  auto signer = *signer_value;
  std::optional<qsafe::crypto::SigningKeyPair> keys;
  const auto keygen_start = Clock::now();
  for (size_t i = 0; i < repetitions; ++i) {
    auto generated = signer.generateKeyPair();
    if (!generated.has_value()) return false;
    keys = std::move(generated);
  }
  const auto keygen_elapsed = Clock::now() - keygen_start;
  if (!keys.has_value()) return false;

  const qsafe::common::Bytes message = {'Q', '-', 'S', 'A', 'F', 'E'};
  std::optional<qsafe::common::Bytes> signature;
  const auto sign_start = Clock::now();
  for (size_t i = 0; i < repetitions; ++i) {
    signature = signer.sign(message, *keys);
    if (!signature.has_value()) return false;
  }
  const auto sign_elapsed = Clock::now() - sign_start;

  const auto verify_start = Clock::now();
  for (size_t i = 0; i < repetitions; ++i) {
    if (!signer.verify(message, *signature, keys->public_key)) return false;
  }
  const auto verify_elapsed = Clock::now() - verify_start;

  std::cout << algorithm << ',' << repetitions << ',' << milliseconds(keygen_elapsed) / repetitions
            << ',' << milliseconds(sign_elapsed) / repetitions << ','
            << milliseconds(verify_elapsed) / repetitions << ',' << keys->public_key.size() << ','
            << signature->size() << '\n';
  return true;
}

}

int main() {
  constexpr size_t repetitions = 10;
  std::cout << "algorithm,repetitions,keygen_ms,sign_ms,verify_ms,public_key_bytes,signature_bytes\n";
  for (const auto& algorithm : std::array<std::string, 2>{"ML-DSA-44", "ML-DSA-65"}) {
    if (!benchmark(algorithm, repetitions)) return 1;
  }
  return 0;
}
