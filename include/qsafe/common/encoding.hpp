#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace qsafe::common {

using Bytes = std::vector<uint8_t>;

class CanonicalWriter {
 public:
  bool writeU8(uint8_t value);
  bool writeU32(uint32_t value);
  bool writeU64(uint64_t value);
  bool writeBytes(const uint8_t* data, size_t size);
  bool writeBytes(const Bytes& value);
  bool writeString(std::string_view value);

  const Bytes& data() const;
  bool valid() const;

 private:
  bool writeLength(uint32_t value);

  Bytes data_;
  bool valid_ = true;
};

class CanonicalReader {
 public:
  explicit CanonicalReader(Bytes data);

  bool readU8(uint8_t& value);
  bool readU32(uint32_t& value);
  bool readU64(uint64_t& value);
  bool readBytes(Bytes& value, size_t max_size);
  bool readString(std::string& value, size_t max_size);

  size_t position() const;
  size_t remaining() const;
  bool finished() const;

 private:
  bool readLength(uint32_t& value, size_t& next_position) const;

  Bytes data_;
  size_t position_ = 0;
};

bool isValidUtf8(std::string_view value);

}
