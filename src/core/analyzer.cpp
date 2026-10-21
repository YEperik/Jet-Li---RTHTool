#include "rth/core/analyzer.hpp"
#include "rth/core/binary_reader.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace rth::core {
namespace {

std::vector<std::uint8_t> readPrefix(BinaryReader& reader, const std::size_t count) {
    const auto actual = static_cast<std::size_t>(std::min<std::uint64_t>(reader.size(), count));
    const auto bytes = reader.readBytes(0, actual);
    std::vector<std::uint8_t> result;
    result.reserve(bytes.size());
    for (const auto value : bytes) result.push_back(std::to_integer<std::uint8_t>(value));
    return result;
}

bool startsWith(const std::vector<std::uint8_t>& bytes,
                const std::initializer_list<std::uint8_t> signature) {
    return bytes.size() >= signature.size() &&
           std::equal(signature.begin(), signature.end(), bytes.begin());
}

std::string hexValue(const std::uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << value;
    return output.str();
}

std::string elfDetails(BinaryReader& reader, const std::vector<std::uint8_t>& prefix) {
    if (prefix.size() < 20) return "ELF magic present, header too short to read e_machine";
    const auto elfClass = prefix[4];
    const auto encoding = prefix[5];
    std::string detail = elfClass == 1 ? "ELF32" : (elfClass == 2 ? "ELF64" : "ELF class unknown");
    detail += encoding == 1 ? ", little-endian" : (encoding == 2 ? ", big-endian" : ", byte order unknown");
    if (encoding != 1 && encoding != 2) return detail;

    const auto read16 = [&](const std::uint64_t offset) {
        return encoding == 1 ? reader.readU16LE(offset) : reader.readU16BE(offset);
    };
    const auto read32 = [&](const std::uint64_t offset) {
        return encoding == 1 ? reader.readU32LE(offset) : reader.readU32BE(offset);
    };
    const auto read64 = [&](const std::uint64_t offset) {
        return encoding == 1 ? reader.readU64LE(offset) : reader.readU64BE(offset);
    };

    const auto type = read16(16);
    const auto machine = read16(18);
    detail += ", e_type=" + hexValue(type) + ", e_machine=" + std::to_string(machine);
    if (machine == 8) detail += " (MIPS)";

    if (elfClass == 1 && reader.size() >= 52) {
        detail += ", e_entry=" + hexValue(read32(24));
        detail += ", e_phoff=" + std::to_string(read32(28));
        detail += ", e_shoff=" + std::to_string(read32(32));
        detail += ", e_phnum=" + std::to_string(read16(44));
        detail += ", e_shnum=" + std::to_string(read16(48));
    } else if (elfClass == 2 && reader.size() >= 64) {
        detail += ", e_entry=" + hexValue(read64(24));
        detail += ", e_phoff=" + std::to_string(read64(32));
        detail += ", e_shoff=" + std::to_string(read64(40));
        detail += ", e_phnum=" + std::to_string(read16(56));
        detail += ", e_shnum=" + std::to_string(read16(60));
    } else {
        detail += ", ELF header incomplete for class-specific offsets";
    }
    return detail;
}

} // namespace

std::string signatureName(const SignatureKind kind) {
    switch (kind) {
        case SignatureKind::Empty: return "empty file";
        case SignatureKind::Elf32LittleEndian: return "ELF32 little-endian";
        case SignatureKind::Elf32BigEndian: return "ELF32 big-endian";
        case SignatureKind::Elf64LittleEndian: return "ELF64 little-endian";
        case SignatureKind::Elf64BigEndian: return "ELF64 big-endian";
        case SignatureKind::MpegPackStart: return "MPEG pack start code (Program Stream candidate)";
        case SignatureKind::MpegSystemHeader: return "MPEG system header start code";
        case SignatureKind::MpegEndCode: return "MPEG end-code-like prefix (not enough to identify file type)";
        case SignatureKind::AllZero: return "all-zero file";
        case SignatureKind::Unknown: return "no known leading signature";
    }
    return "unknown";
}

FileAnalysis analyzeFile(const std::filesystem::path& path, const std::uint64_t chunkSize) {
    if (chunkSize == 0) throw std::invalid_argument("Chunk size must be greater than zero");
    constexpr std::uint64_t maxChunkSize = 64ULL * 1024ULL * 1024ULL;
    if (chunkSize > maxChunkSize) throw std::invalid_argument("Chunk size must not exceed 64 MiB");

    BinaryReader reader(path);
    FileAnalysis result;
    result.path = path;
    result.size = reader.size();
    result.chunkSize = chunkSize;
    result.chunkCount = result.size == 0 ? 0 : ((result.size - 1) / chunkSize) + 1;
    result.firstBytes = readPrefix(reader, 64);

    if (result.size == 0) {
        result.signature = SignatureKind::Empty;
        result.signatureDetails = signatureName(result.signature);
        return result;
    }

    const auto prefix = result.firstBytes;
    if (startsWith(prefix, {0x7f, 0x45, 0x4c, 0x46})) {
        const auto elfClass = prefix.size() > 4 ? prefix[4] : 0;
        const auto encoding = prefix.size() > 5 ? prefix[5] : 0;
        if (elfClass == 1 && encoding == 1) result.signature = SignatureKind::Elf32LittleEndian;
        else if (elfClass == 1 && encoding == 2) result.signature = SignatureKind::Elf32BigEndian;
        else if (elfClass == 2 && encoding == 1) result.signature = SignatureKind::Elf64LittleEndian;
        else if (elfClass == 2 && encoding == 2) result.signature = SignatureKind::Elf64BigEndian;
        else result.signature = SignatureKind::Unknown;
        result.signatureDetails = elfDetails(reader, prefix);
    } else if (startsWith(prefix, {0x00, 0x00, 0x01, 0xba})) {
        result.signature = SignatureKind::MpegPackStart;
        result.signatureDetails = signatureName(result.signature);
    } else if (startsWith(prefix, {0x00, 0x00, 0x01, 0xbb})) {
        result.signature = SignatureKind::MpegSystemHeader;
        result.signatureDetails = signatureName(result.signature);
    } else if (startsWith(prefix, {0x00, 0x00, 0x01, 0xb9})) {
        result.signature = SignatureKind::MpegEndCode;
        result.signatureDetails = signatureName(result.signature);
    } else {
        result.signature = SignatureKind::Unknown;
        result.signatureDetails = signatureName(result.signature);
    }

    std::array<std::uint64_t, 256> frequencies{};
    std::uint64_t zeroCount = 0;
    const auto initialBufferSize = static_cast<std::size_t>(std::min<std::uint64_t>(chunkSize, result.size));
    std::vector<std::byte> buffer(initialBufferSize);
    std::vector<std::byte> firstFullChunk;
    if (result.size >= chunkSize) {
        firstFullChunk.resize(static_cast<std::size_t>(chunkSize));
        reader.read(0, firstFullChunk);
    }

    for (std::uint64_t offset = 0; offset < result.size;) {
        const auto amount64 = std::min<std::uint64_t>(chunkSize, result.size - offset);
        const auto amount = static_cast<std::size_t>(amount64);
        if (buffer.size() < amount) buffer.resize(amount);
        reader.read(offset, std::span<std::byte>(buffer.data(), amount));
        for (std::size_t index = 0; index < amount; ++index) {
            const auto value = std::to_integer<std::uint8_t>(buffer[index]);
            ++frequencies[value];
            if (value == 0) ++zeroCount;
        }
        if (offset > 0 && amount64 == chunkSize && !firstFullChunk.empty() &&
            std::equal(firstFullChunk.begin(), firstFullChunk.end(), buffer.begin())) {
            ++result.fullChunksMatchingFirst;
        }
        offset += amount64;
    }

    result.zeroBytePercent = 100.0 * static_cast<double>(zeroCount) / static_cast<double>(result.size);
    double entropy = 0.0;
    for (const auto count : frequencies) {
        if (count == 0) continue;
        const auto probability = static_cast<double>(count) / static_cast<double>(result.size);
        entropy -= probability * std::log2(probability);
    }
    result.entropyBitsPerByte = entropy;
    if (zeroCount == result.size) {
        result.signature = SignatureKind::AllZero;
        result.signatureDetails = signatureName(result.signature);
    }

    const auto remainder = result.size % chunkSize;
    result.hasPartialTail = result.size > chunkSize && remainder != 0;
    if (result.hasPartialTail && !firstFullChunk.empty()) {
        const auto tail = reader.readBytes(result.size - remainder, static_cast<std::size_t>(remainder));
        result.partialTailMatchesFirstPrefix = std::equal(tail.begin(), tail.end(), firstFullChunk.begin());
    }
    return result;
}

CompareResult compareFiles(const std::filesystem::path& leftPath,
                           const std::filesystem::path& rightPath,
                           const std::size_t bufferSize) {
    if (bufferSize == 0) throw std::invalid_argument("Compare buffer size must be greater than zero");
    BinaryReader left(leftPath);
    BinaryReader right(rightPath);
    CompareResult result;
    result.leftSize = left.size();
    result.rightSize = right.size();
    std::vector<std::byte> leftBuffer(bufferSize);
    std::vector<std::byte> rightBuffer(bufferSize);
    const auto limit = std::min(left.size(), right.size());
    std::uint64_t offset = 0;
    while (offset < limit) {
        const auto amount = static_cast<std::size_t>(std::min<std::uint64_t>(bufferSize, limit - offset));
        left.read(offset, std::span<std::byte>(leftBuffer.data(), amount));
        right.read(offset, std::span<std::byte>(rightBuffer.data(), amount));
        for (std::size_t i = 0; i < amount; ++i) {
            if (leftBuffer[i] != rightBuffer[i]) {
                result.commonPrefixBytes = offset + static_cast<std::uint64_t>(i);
                return result;
            }
        }
        offset += static_cast<std::uint64_t>(amount);
    }
    result.commonPrefixBytes = limit;
    result.leftIsPrefixOfRight = left.size() <= right.size();
    result.rightIsPrefixOfLeft = right.size() <= left.size();
    return result;
}

std::string formatHex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) output << ' ';
        output << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return output.str();
}

} // namespace rth::core
