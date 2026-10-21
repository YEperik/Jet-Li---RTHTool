#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

namespace rth::core {

// Bounds-checked random-access reader; file contents are not loaded wholesale.
class BinaryReader {
public:
    explicit BinaryReader(const std::filesystem::path& path);
    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    void read(std::uint64_t offset, std::span<std::byte> destination);
    [[nodiscard]] std::vector<std::byte> readBytes(std::uint64_t offset, std::size_t count);
    [[nodiscard]] std::uint8_t readU8(std::uint64_t offset);
    [[nodiscard]] std::uint16_t readU16LE(std::uint64_t offset);
    [[nodiscard]] std::uint16_t readU16BE(std::uint64_t offset);
    [[nodiscard]] std::uint32_t readU32LE(std::uint64_t offset);
    [[nodiscard]] std::uint32_t readU32BE(std::uint64_t offset);
    [[nodiscard]] std::uint64_t readU64LE(std::uint64_t offset);
    [[nodiscard]] std::uint64_t readU64BE(std::uint64_t offset);
private:
    void checkRange(std::uint64_t offset, std::uint64_t count) const;
    std::filesystem::path path_;
    std::uint64_t size_{};
    std::ifstream stream_;
};

} // namespace rth::core
