#include "qsafe/common/encoding.hpp"

#include <limits>
#include <utility>

namespace qsafe::common {

namespace {

bool isContinuation(uint8_t value) { return (value & 0xc0U) == 0x80U; }

}

bool isValidUtf8(std::string_view value) {
  size_t index = 0;
  while (index < value.size()) {
    const auto first = static_cast<uint8_t>(value[index]);
    if (first <= 0x7fU) {
      ++index;
      continue;
    }

    size_t continuation_count = 0;
    uint8_t second_min = 0x80U;
    uint8_t second_max = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2;
      if (first == 0xe0U) second_min = 0xa0U;
      if (first == 0xedU) second_max = 0x9fU;
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3;
      if (first == 0xf0U) second_min = 0x90U;
      if (first == 0xf4U) second_max = 0x8fU;
    } else {
      return false;
    }

    if (value.size() - index <= continuation_count) return false;
    const auto second = static_cast<uint8_t>(value[index + 1]);
    if (second < second_min || second > second_max) return false;
    for (size_t offset = 2; offset <= continuation_count; ++offset) {
      if (!isContinuation(static_cast<uint8_t>(value[index + offset]))) return false;
    }
    index += continuation_count + 1;
  }
  return true;
}

bool CanonicalWriter::writeU8(uint8_t value) {
  if (!valid_) return false;
  data_.push_back(value);
  return true;
}

bool CanonicalWriter::writeU32(uint32_t value) {
  if (!valid_) return false;
  for (int shift = 24; shift >= 0; shift -= 8) {
    data_.push_back(static_cast<uint8_t>((value >> shift) & 0xffU));
  }
  return true;
}

bool CanonicalWriter::writeU64(uint64_t value) {
  if (!valid_) return false;
  for (int shift = 56; shift >= 0; shift -= 8) {
    data_.push_back(static_cast<uint8_t>((value >> shift) & 0xffU));
  }
  return true;
}

bool CanonicalWriter::writeLength(uint32_t value) { return writeU32(value); }

bool CanonicalWriter::writeBytes(const uint8_t* data, size_t size) {
  if (!valid_ || (data == nullptr && size != 0) ||
      size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
    valid_ = false;
    return false;
  }
  if (!writeLength(static_cast<uint32_t>(size))) return false;
  if (size != 0) data_.insert(data_.end(), data, data + size);
  return true;
}

bool CanonicalWriter::writeBytes(const Bytes& value) {
  return writeBytes(value.data(), value.size());
}

bool CanonicalWriter::writeString(std::string_view value) {
  if (!isValidUtf8(value) ||
      value.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
    valid_ = false;
    return false;
  }
  return writeBytes(reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

const Bytes& CanonicalWriter::data() const { return data_; }

bool CanonicalWriter::valid() const { return valid_; }

CanonicalReader::CanonicalReader(Bytes data) : data_(std::move(data)) {}

bool CanonicalReader::readU8(uint8_t& value) {
  if (remaining() < 1) return false;
  value = data_[position_];
  ++position_;
  return true;
}

bool CanonicalReader::readU32(uint32_t& value) {
  if (remaining() < 4) return false;
  uint32_t parsed = 0;
  for (size_t i = 0; i < 4; ++i) parsed = (parsed << 8) | data_[position_ + i];
  value = parsed;
  position_ += 4;
  return true;
}

bool CanonicalReader::readU64(uint64_t& value) {
  if (remaining() < 8) return false;
  uint64_t parsed = 0;
  for (size_t i = 0; i < 8; ++i) parsed = (parsed << 8) | data_[position_ + i];
  value = parsed;
  position_ += 8;
  return true;
}

bool CanonicalReader::readLength(uint32_t& value, size_t& next_position) const {
  if (data_.size() - position_ < 4) return false;
  uint32_t parsed = 0;
  for (size_t i = 0; i < 4; ++i) parsed = (parsed << 8) | data_[position_ + i];
  value = parsed;
  next_position = position_ + 4;
  return true;
}

bool CanonicalReader::readBytes(Bytes& value, size_t max_size) {
  uint32_t length = 0;
  size_t next_position = 0;
  if (!readLength(length, next_position) || length > max_size ||
      static_cast<size_t>(length) > data_.size() - next_position) {
    return false;
  }
  Bytes parsed(data_.begin() + static_cast<std::ptrdiff_t>(next_position),
               data_.begin() + static_cast<std::ptrdiff_t>(next_position + length));
  value = std::move(parsed);
  position_ = next_position + length;
  return true;
}

bool CanonicalReader::readString(std::string& value, size_t max_size) {
  uint32_t length = 0;
  size_t next_position = 0;
  if (!readLength(length, next_position) || length > max_size ||
      static_cast<size_t>(length) > data_.size() - next_position) {
    return false;
  }
  const std::string_view parsed(
      reinterpret_cast<const char*>(data_.data() + next_position), length);
  if (!isValidUtf8(parsed)) return false;
  value.assign(parsed.data(), parsed.size());
  position_ = next_position + length;
  return true;
}

size_t CanonicalReader::position() const { return position_; }

size_t CanonicalReader::remaining() const { return data_.size() - position_; }

bool CanonicalReader::finished() const { return position_ == data_.size(); }

}
