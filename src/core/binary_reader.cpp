#include "rth/core/binary_reader.hpp"

#include <limits>
#include <stdexcept>
#include <string>

namespace rth::core {

BinaryReader::BinaryReader(const std::filesystem::path& path)
    : path_(path), stream_(path, std::ios::binary) {
    if (!stream_) throw std::runtime_error("Unable to open file: " + path.string());
    std::error_code error;
    const auto fileSize = std::filesystem::file_size(path, error);
    if (error) throw std::runtime_error("Unable to determine file size for " + path.string() + ": " + error.message());
    size_ = fileSize;
}

void BinaryReader::checkRange(const std::uint64_t offset, const std::uint64_t count) const {
    if (offset > size_ || count > size_ - offset)
        throw std::out_of_range("Read outside file bounds: offset=" + std::to_string(offset) +
                                ", count=" + std::to_string(count) + ", size=" + std::to_string(size_));
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
        count > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max()))
        throw std::out_of_range("Requested read exceeds stream API limits");
}

void BinaryReader::read(const std::uint64_t offset, const std::span<std::byte> destination) {
    checkRange(offset, static_cast<std::uint64_t>(destination.size()));
    if (destination.empty()) return;
    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_) throw std::runtime_error("Seek failed in file: " + path_.string());
    stream_.read(reinterpret_cast<char*>(destination.data()), static_cast<std::streamsize>(destination.size()));
    if (stream_.gcount() != static_cast<std::streamsize>(destination.size()))
        throw std::runtime_error("Short read in file: " + path_.string());
}

std::vector<std::byte> BinaryReader::readBytes(const std::uint64_t offset, const std::size_t count) {
    checkRange(offset, static_cast<std::uint64_t>(count));
    std::vector<std::byte> bytes(count);
    read(offset, bytes);
    return bytes;
}
std::uint8_t BinaryReader::readU8(const std::uint64_t offset) {
    return std::to_integer<std::uint8_t>(readBytes(offset, 1)[0]);
}
std::uint16_t BinaryReader::readU16LE(const std::uint64_t offset) {
    const auto b = readBytes(offset, 2);
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[0])) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[1])) << 8U);
}
std::uint16_t BinaryReader::readU16BE(const std::uint64_t offset) {
    const auto b = readBytes(offset, 2);
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[0])) << 8U) |
           static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[1]));
}
std::uint32_t BinaryReader::readU32LE(const std::uint64_t offset) {
    const auto b = readBytes(offset, 4);
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[0])) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[1])) << 8U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[2])) << 16U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[3])) << 24U);
}
std::uint32_t BinaryReader::readU32BE(const std::uint64_t offset) {
    const auto b = readBytes(offset, 4);
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[0])) << 24U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[1])) << 16U) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[2])) << 8U) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b[3]));
}
std::uint64_t BinaryReader::readU64LE(const std::uint64_t offset) {
    const auto b = readBytes(offset, 8);
    std::uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(b[i])) << (i * 8U);
    return value;
}
std::uint64_t BinaryReader::readU64BE(const std::uint64_t offset) {
    const auto b = readBytes(offset, 8);
    std::uint64_t value = 0;
    for (const auto byte : b) value = (value << 8U) | std::to_integer<std::uint8_t>(byte);
    return value;
}

} // namespace rth::core
