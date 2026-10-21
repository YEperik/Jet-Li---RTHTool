#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rth::core {

enum class SignatureKind {
    Empty, Elf32LittleEndian, Elf32BigEndian, Elf64LittleEndian, Elf64BigEndian,
    MpegPackStart, MpegSystemHeader, MpegEndCode, AllZero, Unknown
};

struct FileAnalysis {
    std::filesystem::path path;
    std::uint64_t size{};
    SignatureKind signature{SignatureKind::Unknown};
    std::string signatureDetails;
    double entropyBitsPerByte{};
    double zeroBytePercent{};
    std::uint64_t chunkSize{};
    std::uint64_t chunkCount{};
    std::uint64_t fullChunksMatchingFirst{}; // Does not include the first chunk itself.
    bool hasPartialTail{};
    bool partialTailMatchesFirstPrefix{};
    std::vector<std::uint8_t> firstBytes;
};

struct CompareResult {
    std::uint64_t commonPrefixBytes{};
    std::uint64_t leftSize{};
    std::uint64_t rightSize{};
    bool leftIsPrefixOfRight{};
    bool rightIsPrefixOfLeft{};
};

[[nodiscard]] FileAnalysis analyzeFile(const std::filesystem::path& path,
                                       std::uint64_t chunkSize = 0x40000);
[[nodiscard]] CompareResult compareFiles(const std::filesystem::path& left,
                                         const std::filesystem::path& right,
                                         std::size_t bufferSize = 1024 * 1024);
[[nodiscard]] std::string signatureName(SignatureKind kind);
[[nodiscard]] std::string formatHex(const std::vector<std::uint8_t>& bytes);

} // namespace rth::core
