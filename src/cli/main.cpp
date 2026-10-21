#include "rth/core/analyzer.hpp"
#include "rth/core/binary_reader.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::uint64_t parseNumber(const std::string& text, const char* fieldName) {
    if (text.empty() || text.front() == '-') {
        throw std::invalid_argument(std::string("Invalid ") + fieldName + ": " + text);
    }
    std::size_t consumed = 0;
    try {
        const auto value = std::stoull(text, &consumed, 0);
        if (consumed != text.size()) throw std::invalid_argument("trailing characters");
        return value;
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string("Invalid ") + fieldName + ": " + text +
                                    " (use decimal or 0x-prefixed hexadecimal)");
    }
}

std::string boolText(const bool value) { return value ? "yes" : "no"; }

void printUsage() {
    std::cout <<
        "RTH Modding Tool 0.1.0 — evidence-first PS2 binary inspection\n\n"
        "Usage:\n"
        "  rthtool inspect <file> [chunk-size]\n"
        "  rthtool compare <left-file> <right-file>\n"
        "  rthtool hex <file> [offset] [count]\n\n"
        "Numbers accept decimal or 0x-prefixed hexadecimal. Default chunk-size is 0x40000.\n";
}

int inspect(const std::string& path, const std::uint64_t chunkSize) {
    const auto result = rth::core::analyzeFile(path, chunkSize);
    std::cout << "File: " << result.path.string() << '\n'
              << "Size: " << result.size << " bytes\n"
              << "Leading signature: " << result.signatureDetails << '\n'
              << "First bytes: " << rth::core::formatHex(result.firstBytes) << '\n'
              << std::fixed << std::setprecision(4)
              << "Shannon entropy: " << result.entropyBitsPerByte << " bits/byte\n"
              << "Zero bytes: " << result.zeroBytePercent << "%\n"
              << "Chunk size: " << result.chunkSize << " bytes (0x" << std::hex << result.chunkSize << std::dec << ")\n"
              << "Chunk count: " << result.chunkCount << '\n'
              << "Full chunks after the first matching the first chunk: " << result.fullChunksMatchingFirst << '\n'
              << "Partial tail after one or more full chunks: " << boolText(result.hasPartialTail) << '\n';
    if (result.hasPartialTail) {
        std::cout << "Partial tail matches prefix of first chunk: "
                  << boolText(result.partialTailMatchesFirstPrefix) << '\n';
    }
    return 0;
}

int compare(const std::string& leftPath, const std::string& rightPath) {
    const auto result = rth::core::compareFiles(leftPath, rightPath);
    std::cout << "Left:  " << leftPath << " (" << result.leftSize << " bytes)\n"
              << "Right: " << rightPath << " (" << result.rightSize << " bytes)\n"
              << "Common prefix: " << result.commonPrefixBytes << " bytes (0x"
              << std::hex << result.commonPrefixBytes << std::dec << ")\n"
              << "Left is a prefix of right: " << boolText(result.leftIsPrefixOfRight) << '\n'
              << "Right is a prefix of left: " << boolText(result.rightIsPrefixOfLeft) << '\n';
    return 0;
}

int hexDump(const std::string& path, const std::uint64_t offset, const std::uint64_t count) {
    if (count > 1024 * 1024) throw std::invalid_argument("Hex dump limit is 1 MiB per invocation");
    rth::core::BinaryReader reader(path);
    const auto actual64 = offset < reader.size() ? std::min(count, reader.size() - offset) : 0;
    const auto actual = static_cast<std::size_t>(actual64);
    const auto data = reader.readBytes(offset, actual);

    std::cout << "Hex dump: " << path << " @ 0x" << std::hex << offset << std::dec
              << " (" << actual << " bytes)\n";
    for (std::size_t row = 0; row < actual; row += 16) {
        std::cout << std::hex << std::setw(8) << std::setfill('0')
                  << (offset + static_cast<std::uint64_t>(row)) << "  ";
        for (std::size_t column = 0; column < 16; ++column) {
            if (row + column < actual) {
                std::cout << std::setw(2) << std::to_integer<unsigned int>(data[row + column]) << ' ';
            } else {
                std::cout << "   ";
            }
        }
        std::cout << " |";
        for (std::size_t column = 0; column < 16 && row + column < actual; ++column) {
            const auto value = std::to_integer<unsigned char>(data[row + column]);
            std::cout << (value >= 32 && value <= 126 ? static_cast<char>(value) : '.');
        }
        std::cout << "|\n";
    }
    return 0;
}

} // namespace

int main(const int argc, char** argv) {
    try {
        if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
            printUsage();
            return argc < 2 ? 2 : 0;
        }
        const std::string command = argv[1];
        if (command == "inspect") {
            if (argc < 3 || argc > 4) { printUsage(); return 2; }
            const auto chunkSize = argc == 4 ? parseNumber(argv[3], "chunk size") : 0x40000ULL;
            return inspect(argv[2], chunkSize);
        }
        if (command == "compare") {
            if (argc != 4) { printUsage(); return 2; }
            return compare(argv[2], argv[3]);
        }
        if (command == "hex") {
            if (argc < 3 || argc > 5) { printUsage(); return 2; }
            const auto offset = argc >= 4 ? parseNumber(argv[3], "offset") : 0ULL;
            const auto count = argc == 5 ? parseNumber(argv[4], "count") : 256ULL;
            return hexDump(argv[2], offset, count);
        }
        printUsage();
        std::cerr << "Unknown command: " << command << '\n';
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
