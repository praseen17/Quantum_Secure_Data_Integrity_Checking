#include "qsafe/vault/workspace.hpp"

#include "qsafe/crypto/hash.hpp"
#include "qsafe/merkle/merkle_tree.hpp"
#include "qsafe/repair/reed_solomon_codec.hpp"
#include "qsafe/storage/chunker.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <system_error>

namespace qsafe::vault {
namespace {

constexpr uint32_t kDataShards = 4;
constexpr uint32_t kParityShards = 2;
constexpr uint32_t kStripeWidth = kDataShards + kParityShards;
constexpr uint64_t kMaximumInputBytes = 256ULL * 1024 * 1024;
constexpr size_t kMaximumMetadataBytes = 1024 * 1024;
const std::filesystem::path kMetadataName = "workspace.qsv";

bool writeFile(const std::filesystem::path& path, const common::Bytes& bytes,
               std::string& error) {
  std::error_code ec;
  if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    error = "cannot create workspace directory: " + ec.message();
    return false;
  }
  auto temporary = path;
  temporary += ".tmp";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) {
      error = "cannot open workspace metadata for writing";
      return false;
    }
    if (!bytes.empty()) {
      output.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    output.close();
    if (!output) {
      std::filesystem::remove(temporary, ec);
      error = "failed writing workspace metadata";
      return false;
    }
  }
  std::filesystem::rename(temporary, path, ec);
  if (ec) {
    std::filesystem::remove(temporary, ec);
    error = "failed replacing workspace metadata";
    return false;
  }
  std::filesystem::permissions(path, std::filesystem::perms::owner_read |
                                        std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, ec);
  error.clear();
  return true;
}

std::optional<common::Bytes> readFile(const std::filesystem::path& path, size_t maximum,
                                      std::string& error) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    error = "workspace file is missing or unreadable";
    return std::nullopt;
  }
  const auto length = input.tellg();
  if (length < 0 || static_cast<uint64_t>(length) > maximum) {
    error = "workspace file exceeds the configured size limit";
    return std::nullopt;
  }
  common::Bytes bytes(static_cast<size_t>(length));
  input.seekg(0);
  if (!bytes.empty()) {
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
  if (!input) {
    error = "failed reading workspace file";
    return std::nullopt;
  }
  error.clear();
  return bytes;
}

std::optional<common::Bytes> serializeWorkspace(const WorkspaceInfo& info) {
  const auto encoded_manifest = manifest::serialize(info.signed_manifest);
  if (!encoded_manifest.has_value()) return std::nullopt;
  common::CanonicalWriter writer;
  if (!writer.writeString("QSAFE_WORKSPACE_PAYLOAD_V1") || !writer.writeString(info.file_id) ||
      !writer.writeU64(info.version) || !writer.writeU64(info.original_length) ||
      !writer.writeU64(info.source_shard_count) || !writer.writeU64(info.shard_size) ||
      !writer.writeBytes(*encoded_manifest) || !writer.writeBytes(info.manifest_signature) ||
      !writer.writeBytes(info.owner_public_key)) {
    return std::nullopt;
  }
  return writer.data();
}

std::optional<WorkspaceInfo> parseWorkspace(const common::Bytes& encoded, std::string& error) {
  common::CanonicalReader envelope(encoded);
  std::string envelope_magic;
  common::Bytes payload;
  WorkspaceInfo info;
  if (!envelope.readString(envelope_magic, 64) || envelope_magic != "QSAFE_WORKSPACE_ENVELOPE_V1" ||
      !envelope.readBytes(payload, kMaximumMetadataBytes) ||
      !envelope.readBytes(info.workspace_signature, 16 * 1024) || !envelope.finished()) {
    error = "workspace signature envelope is malformed";
    return std::nullopt;
  }
  common::CanonicalReader reader(payload);
  std::string magic;
  common::Bytes manifest_bytes;
  if (!reader.readString(magic, 64) || magic != "QSAFE_WORKSPACE_PAYLOAD_V1" ||
      !reader.readString(info.file_id, 256) || !reader.readU64(info.version) ||
      !reader.readU64(info.original_length) || !reader.readU64(info.source_shard_count) ||
      !reader.readU64(info.shard_size) || !reader.readBytes(manifest_bytes, 64 * 1024) ||
      !reader.readBytes(info.manifest_signature, 16 * 1024) ||
      !reader.readBytes(info.owner_public_key, 16 * 1024) || !reader.finished()) {
    error = "workspace metadata is malformed";
    return std::nullopt;
  }
  const auto decoded_manifest = manifest::deserialize(manifest_bytes);
  if (!decoded_manifest.has_value() || info.version == 0 || info.shard_size == 0) {
    error = "workspace manifest or metadata is invalid";
    return std::nullopt;
  }
  info.signed_manifest = *decoded_manifest;
  const uint64_t expected_source_count = info.original_length / info.shard_size +
                                        (info.original_length % info.shard_size != 0);
  if (info.signed_manifest.file_id != info.file_id ||
      info.signed_manifest.version != info.version || info.signed_manifest.data_shards != kDataShards ||
      info.signed_manifest.parity_shards != kParityShards ||
      info.signed_manifest.shard_count == 0 || info.signed_manifest.shard_count % kStripeWidth != 0 ||
      info.source_shard_count != expected_source_count ||
      info.source_shard_count > info.signed_manifest.shard_count / kStripeWidth * kDataShards) {
    error = "workspace fields do not match the signed manifest";
    return std::nullopt;
  }
  std::string signer_error;
  const auto signer = crypto::LiboqsSigner::create("ML-DSA-44", signer_error);
  if (!signer.has_value() ||
      !manifest::verify(info.signed_manifest, info.manifest_signature, *signer,
                        info.owner_public_key) ||
      !signer->verify(payload, info.workspace_signature, info.owner_public_key)) {
    error = "workspace metadata or manifest owner signature is invalid";
    return std::nullopt;
  }
  error.clear();
  return info;
}

std::optional<WorkspaceInfo> loadWorkspace(const std::filesystem::path& workspace,
                                           std::string& error) {
  const auto encoded = readFile(workspace / kMetadataName, kMaximumMetadataBytes, error);
  if (!encoded.has_value()) return std::nullopt;
  return parseWorkspace(*encoded, error);
}

std::optional<std::string> newFileId() {
  std::array<uint8_t, 16> random{};
  if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) return std::nullopt;
  static constexpr char digits[] = "0123456789abcdef";
  std::string output = "qsafe-";
  output.reserve(6 + random.size() * 2);
  for (const uint8_t byte : random) {
    output.push_back(digits[byte >> 4]);
    output.push_back(digits[byte & 0x0f]);
  }
  return output;
}

std::optional<std::vector<crypto::Hash>> proofsFor(const std::vector<common::Bytes>& shards,
                                                   const std::string& file_id,
                                                   uint64_t version,
                                                   std::vector<crypto::Hash>& leaves) {
  leaves.clear();
  leaves.reserve(shards.size());
  for (size_t i = 0; i < shards.size(); ++i) {
    const auto leaf = crypto::leafHash(file_id, version, i, shards[i]);
    if (!leaf.has_value()) return std::nullopt;
    leaves.push_back(*leaf);
  }
  return leaves;
}

}

std::optional<WorkspaceInfo> ingestFile(const std::filesystem::path& input_path,
                                        const std::filesystem::path& workspace,
                                        std::string& error) {
  std::error_code ec;
  if (std::filesystem::exists(workspace / kMetadataName, ec)) {
    error = "workspace already contains an ingested file";
    return std::nullopt;
  }
  auto input = readFile(input_path, static_cast<size_t>(kMaximumInputBytes), error);
  if (!input.has_value()) return std::nullopt;
  const auto chunked = storage::FileChunker::split(*input);
  if (!chunked.has_value()) {
    error = "input could not be split into fixed-size shards";
    return std::nullopt;
  }
  const uint64_t source_shard_count = chunked->shards.size();
  const uint64_t minimum_data_shards = std::max<uint64_t>(source_shard_count, 1);
  const uint64_t stripe_count = (minimum_data_shards + kDataShards - 1) / kDataShards;
  if (stripe_count > std::numeric_limits<size_t>::max() / kStripeWidth) {
    error = "input requires too many stripes";
    return std::nullopt;
  }
  auto file_id = newFileId();
  if (!file_id.has_value()) {
    error = "operating system CSPRNG failed while creating file identity";
    return std::nullopt;
  }
  std::string signer_error;
  const auto signer = crypto::LiboqsSigner::create("ML-DSA-44", signer_error);
  if (!signer.has_value()) {
    error = signer_error;
    return std::nullopt;
  }
  auto owner_keys = signer->generateKeyPair();
  if (!owner_keys.has_value()) {
    error = "owner signing key generation failed";
    return std::nullopt;
  }
  std::string codec_error;
  const auto codec = repair::ReedSolomonCodec::create(kDataShards, kParityShards, codec_error);
  if (!codec.has_value()) {
    error = codec_error;
    return std::nullopt;
  }

  std::vector<common::Bytes> shards;
  shards.reserve(static_cast<size_t>(stripe_count * kStripeWidth));
  const size_t shard_size = chunked->shard_size;
  for (uint64_t stripe = 0; stripe < stripe_count; ++stripe) {
    std::vector<common::Bytes> data;
    data.reserve(kDataShards);
    for (uint32_t local = 0; local < kDataShards; ++local) {
      const uint64_t source_index = stripe * kDataShards + local;
      if (source_index < source_shard_count) {
        data.push_back(chunked->shards[static_cast<size_t>(source_index)]);
      } else {
        data.emplace_back(shard_size, 0);
      }
    }
    const auto parity = codec->encodeStripe(data);
    if (!parity.has_value()) {
      error = "ISA-L failed to encode an input stripe";
      return std::nullopt;
    }
    for (auto& shard : data) shards.push_back(std::move(shard));
    for (const auto& shard : *parity) shards.push_back(shard);
  }

  std::vector<crypto::Hash> leaves;
  if (!proofsFor(shards, *file_id, 1, leaves).has_value()) {
    error = "failed hashing input shards";
    return std::nullopt;
  }
  const auto tree = merkle::MerkleTree::build(leaves);
  if (!tree.has_value()) {
    error = "failed building input Merkle tree";
    return std::nullopt;
  }
  std::vector<std::vector<crypto::Hash>> paths;
  paths.reserve(shards.size());
  for (size_t index = 0; index < shards.size(); ++index) {
    const auto path = tree->path(index);
    if (!path.has_value()) {
      error = "failed constructing a Merkle inclusion proof";
      return std::nullopt;
    }
    paths.push_back(*path);
  }

  WorkspaceInfo info;
  info.file_id = *file_id;
  info.original_length = input->size();
  info.source_shard_count = source_shard_count;
  info.shard_size = shard_size;
  info.signed_manifest.file_id = *file_id;
  info.signed_manifest.version = 1;
  info.signed_manifest.root = tree->root();
  info.signed_manifest.shard_count = shards.size();
  info.signed_manifest.data_shards = kDataShards;
  info.signed_manifest.parity_shards = kParityShards;
  info.signed_manifest.codec = "ISA-L-RS";
  info.signed_manifest.hash_id = "SHA-256";
  info.signed_manifest.protocol_version = 1;
  const auto signature = manifest::sign(info.signed_manifest, *signer, *owner_keys);
  if (!signature.has_value()) {
    error = "failed signing file manifest";
    return std::nullopt;
  }
  info.manifest_signature = *signature;
  info.owner_public_key = owner_keys->public_key;

  std::filesystem::create_directories(workspace, ec);
  if (ec) {
    error = "cannot create workspace: " + ec.message();
    return std::nullopt;
  }
  std::filesystem::permissions(workspace, std::filesystem::perms::owner_all,
                                std::filesystem::perm_options::replace, ec);
  if (ec) {
    error = "cannot restrict workspace permissions: " + ec.message();
    return std::nullopt;
  }
  auto cloud = storage::CloudStorage::open(workspace / "cloud", error);
  if (!cloud.has_value() || !cloud->put(info.file_id, info.version, shards, paths, error)) {
    return std::nullopt;
  }
  for (std::filesystem::recursive_directory_iterator it(workspace, ec), end; it != end && !ec;
       it.increment(ec)) {
    const auto permissions = it->is_directory(ec)
        ? std::filesystem::perms::owner_all
        : std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    if (!ec) std::filesystem::permissions(it->path(), permissions,
                                           std::filesystem::perm_options::replace, ec);
    if (ec) {
      error = "cannot restrict stored file permissions: " + ec.message();
      return std::nullopt;
    }
  }
  if (ec) {
    error = "cannot inspect workspace files: " + ec.message();
    return std::nullopt;
  }
  const auto encoded_workspace = serializeWorkspace(info);
  if (!encoded_workspace.has_value()) {
    error = "failed serializing workspace metadata";
    return std::nullopt;
  }
  const auto workspace_signature = signer->sign(*encoded_workspace, *owner_keys);
  if (!workspace_signature.has_value()) {
    error = "failed signing workspace metadata";
    return std::nullopt;
  }
  info.workspace_signature = *workspace_signature;
  common::CanonicalWriter envelope;
  if (!envelope.writeString("QSAFE_WORKSPACE_ENVELOPE_V1") ||
      !envelope.writeBytes(*encoded_workspace) || !envelope.writeBytes(*workspace_signature) ||
      !writeFile(workspace / kMetadataName, envelope.data(), error)) {
    return std::nullopt;
  }
  error.clear();
  return info;
}

std::optional<WorkspaceInfo> inspectWorkspace(const std::filesystem::path& workspace,
                                              std::string& error) {
  return loadWorkspace(workspace, error);
}

std::optional<audit::AuditResult> auditFile(const std::filesystem::path& workspace,
                                            uint64_t sample_count, std::string& error) {
  const auto info = loadWorkspace(workspace, error);
  if (!info.has_value()) return std::nullopt;
  if (sample_count == 0 || sample_count > info->signed_manifest.shard_count) {
    error = "sample count must be between one and the total shard count";
    return std::nullopt;
  }
  std::string signer_error;
  const auto signer = crypto::LiboqsSigner::create("ML-DSA-44", signer_error);
  if (!signer.has_value()) {
    error = signer_error;
    return std::nullopt;
  }
  std::string storage_error;
  auto cloud = storage::CloudStorage::open(workspace / "cloud", storage_error);
  if (!cloud.has_value()) {
    error = storage_error;
    return std::nullopt;
  }
  std::string challenge_error;
  const auto challenge = audit::createChallenge(info->file_id, info->version,
      info->signed_manifest.shard_count, sample_count, challenge_error);
  if (!challenge.has_value()) {
    error = challenge_error;
    return std::nullopt;
  }
  const auto response = audit::makeResponse(*challenge, *cloud);
  const auto result = audit::verifyResponse(info->signed_manifest, info->manifest_signature,
      *signer, info->owner_public_key, {info->file_id, info->version}, *challenge, response);
  error.clear();
  return result;
}

bool markShardUnavailable(const std::filesystem::path& workspace, uint64_t index,
                          std::string& error) {
  const auto info = loadWorkspace(workspace, error);
  if (!info.has_value()) return false;
  if (index >= info->signed_manifest.shard_count) {
    error = "shard index is outside the manifest";
    return false;
  }
  auto cloud = storage::CloudStorage::open(workspace / "cloud", error);
  if (!cloud.has_value()) return false;
  return cloud->setAvailability(info->file_id, info->version, index,
                                storage::ShardAvailability::Unavailable, error);
}

repair::RepairResult recoverShard(const std::filesystem::path& workspace, uint64_t index) {
  std::string error;
  const auto info = loadWorkspace(workspace, error);
  if (!info.has_value()) {
    repair::RepairResult result;
    result.status = repair::RepairStatus::InvalidManifest;
    result.error = error;
    result.repaired_index = index;
    return result;
  }
  std::string signer_error;
  const auto signer = crypto::LiboqsSigner::create("ML-DSA-44", signer_error);
  if (!signer.has_value()) {
    repair::RepairResult result;
    result.status = repair::RepairStatus::InvalidManifest;
    result.error = signer_error;
    result.repaired_index = index;
    return result;
  }
  auto cloud = storage::CloudStorage::open(workspace / "cloud", error);
  if (!cloud.has_value()) {
    repair::RepairResult result;
    result.status = repair::RepairStatus::StorageError;
    result.error = error;
    result.repaired_index = index;
    return result;
  }
  return repair::repairShard(info->signed_manifest, info->manifest_signature, *signer,
      info->owner_public_key, {info->file_id, info->version}, *cloud, index);
}

bool restoreFile(const std::filesystem::path& workspace,
                 const std::filesystem::path& output_path, std::string& error) {
  const auto info = loadWorkspace(workspace, error);
  if (!info.has_value()) return false;
  std::string storage_error;
  auto cloud = storage::CloudStorage::open(workspace / "cloud", storage_error);
  if (!cloud.has_value()) {
    error = storage_error;
    return false;
  }
  common::Bytes restored;
  if (info->original_length > std::numeric_limits<size_t>::max()) {
    error = "restored file exceeds this platform's address space";
    return false;
  }
  restored.reserve(static_cast<size_t>(info->source_shard_count * info->shard_size));
  for (uint64_t source_index = 0; source_index < info->source_shard_count; ++source_index) {
    const uint64_t stripe = source_index / kDataShards;
    const uint64_t local = source_index % kDataShards;
    const uint64_t global_index = stripe * kStripeWidth + local;
    const auto shard = cloud->getShard(info->file_id, info->version, global_index);
    const auto proof = cloud->getPath(info->file_id, info->version, global_index);
    if (shard.status != storage::ReadStatus::Available || !proof.has_value()) {
      error = "a required data shard or proof is unavailable; repair missing shards first";
      return false;
    }
    const auto leaf = crypto::leafHash(info->file_id, info->version, global_index, shard.bytes);
    if (!leaf.has_value() || !merkle::MerkleTree::verify(*leaf, global_index,
            info->signed_manifest.shard_count, *proof, info->signed_manifest.root)) {
      error = "a data shard failed verification against the signed manifest";
      return false;
    }
    restored.insert(restored.end(), shard.bytes.begin(), shard.bytes.end());
  }
  if (restored.size() < info->original_length) {
    error = "restored data is shorter than the original file";
    return false;
  }
  restored.resize(static_cast<size_t>(info->original_length));
  if (!writeFile(output_path, restored, error)) return false;
  error.clear();
  return true;
}

}
