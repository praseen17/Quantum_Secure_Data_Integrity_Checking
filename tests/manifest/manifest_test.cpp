#include "qsafe/crypto/signature.hpp"
#include "qsafe/manifest/manifest.hpp"

#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <vector>

namespace qsafe::manifest {

namespace {

Manifest sampleManifest() {
  Manifest manifest;
  manifest.file_id = "file-42";
  manifest.version = 3;
  manifest.root[0] = 0xa5;
  manifest.shard_count = 12;
  manifest.data_shards = 4;
  manifest.parity_shards = 2;
  manifest.codec = "ISA-L-RS";
  manifest.hash_id = "SHA-256";
  manifest.protocol_version = 1;
  return manifest;
}

crypto::LiboqsSigner makeSigner() {
  std::string error;
  auto signer = crypto::LiboqsSigner::create("ML-DSA-44", error);
  if (!signer.has_value()) throw std::runtime_error(error);
  return *signer;
}

}

TEST(Manifest, CanonicalRoundTripPreservesEveryField) {
  const auto manifest = sampleManifest();
  const auto encoded = serialize(manifest);
  ASSERT_TRUE(encoded.has_value());
  const auto decoded = deserialize(*encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(*decoded, manifest);
}

TEST(Manifest, RejectsInvalidParametersTruncationAndTrailingBytes) {
  auto invalid = sampleManifest();
  invalid.file_id.clear();
  EXPECT_FALSE(serialize(invalid).has_value());

  invalid = sampleManifest();
  invalid.data_shards = 0;
  EXPECT_FALSE(serialize(invalid).has_value());

  invalid = sampleManifest();
  invalid.shard_count = 11;
  EXPECT_FALSE(serialize(invalid).has_value());

  const auto encoded = serialize(sampleManifest());
  ASSERT_TRUE(encoded.has_value());
  auto truncated = *encoded;
  truncated.pop_back();
  EXPECT_FALSE(deserialize(truncated).has_value());
  auto extended = *encoded;
  extended.push_back(0);
  EXPECT_FALSE(deserialize(extended).has_value());
}

TEST(Manifest, SignatureVerifiesAgainstTrustedOwnerKey) {
  auto signer = makeSigner();
  auto keys = signer.generateKeyPair();
  ASSERT_TRUE(keys.has_value());
  const auto manifest = sampleManifest();
  const auto signature = sign(manifest, signer, *keys);
  ASSERT_TRUE(signature.has_value());
  EXPECT_TRUE(verify(manifest, *signature, signer, keys->public_key));
}

TEST(Manifest, ChangingAnySignedFieldInvalidatesSignature) {
  auto signer = makeSigner();
  auto keys = signer.generateKeyPair();
  ASSERT_TRUE(keys.has_value());
  const auto original = sampleManifest();
  const auto signature = sign(original, signer, *keys);
  ASSERT_TRUE(signature.has_value());

  const std::vector<std::function<void(Manifest&)>> changes = {
      [](Manifest& value) { value.file_id += "x"; },
      [](Manifest& value) { ++value.version; },
      [](Manifest& value) { value.root[0] ^= 1; },
      [](Manifest& value) { ++value.shard_count; },
      [](Manifest& value) { ++value.data_shards; },
      [](Manifest& value) { ++value.parity_shards; },
      [](Manifest& value) { value.codec += "x"; },
      [](Manifest& value) { value.hash_id += "x"; },
      [](Manifest& value) { ++value.protocol_version; }};

  for (const auto& change : changes) {
    auto modified = original;
    change(modified);
    EXPECT_FALSE(verify(modified, *signature, signer, keys->public_key));
  }
}

TEST(Manifest, RejectsWrongTrustedKeyAndTruncatedSignature) {
  auto signer = makeSigner();
  auto owner_keys = signer.generateKeyPair();
  auto other_keys = signer.generateKeyPair();
  ASSERT_TRUE(owner_keys.has_value());
  ASSERT_TRUE(other_keys.has_value());
  const auto manifest = sampleManifest();
  const auto signature = sign(manifest, signer, *owner_keys);
  ASSERT_TRUE(signature.has_value());
  EXPECT_FALSE(verify(manifest, *signature, signer, other_keys->public_key));

  auto truncated = *signature;
  truncated.pop_back();
  EXPECT_FALSE(verify(manifest, truncated, signer, owner_keys->public_key));
}

TEST(Manifest, UnsupportedAlgorithmReturnsClearError) {
  std::string error;
  const auto signer = crypto::LiboqsSigner::create("NOT-A-SIGNATURE", error);
  EXPECT_FALSE(signer.has_value());
  EXPECT_NE(error.find("unsupported"), std::string::npos);
}

}
