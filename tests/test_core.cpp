#include "rth/core/analyzer.hpp"
#include "rth/core/binary_reader.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

class TempFile {
public:
    TempFile(const std::string& name, const std::vector<unsigned char>& data)
        : path_(std::filesystem::temp_directory_path() / ("rth_test_" + name)) {
        std::ofstream output(path_, std::ios::binary);
        if (!output) throw std::runtime_error("Unable to create test fixture");
        for (const auto value : data) output.put(static_cast<char>(value));
        if (!output) throw std::runtime_error("Unable to write test fixture");
    }
    ~TempFile() { std::error_code ignored; std::filesystem::remove(path_, ignored); }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }
private:
    std::filesystem::path path_;
};

void testEndianReadsAndBounds() {
    const TempFile fixture("endian.bin", {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
    rth::core::BinaryReader reader(fixture.path());
    require(reader.size() == 8, "size must be 8");
    require(reader.readU8(0) == 1, "readU8 mismatch");
    require(reader.readU16LE(0) == 0x0201, "readU16LE mismatch");
    require(reader.readU16BE(0) == 0x0102, "readU16BE mismatch");
    require(reader.readU32LE(0) == 0x04030201, "readU32LE mismatch");
    require(reader.readU32BE(0) == 0x01020304, "readU32BE mismatch");
    require(reader.readU64LE(0) == 0x0807060504030201ULL, "readU64LE mismatch");
    require(reader.readU64BE(0) == 0x0102030405060708ULL, "readU64BE mismatch");
    bool rejected = false;
    try { (void)reader.readU32LE(6); } catch (const std::out_of_range&) { rejected = true; }
    require(rejected, "out-of-bounds read must throw");
}

void testRepeatedChunksAndTail() {
    const TempFile fixture("repeat.bin", {1, 2, 3, 4, 1, 2, 3, 4, 1, 2});
    const auto result = rth::core::analyzeFile(fixture.path(), 4);
    require(result.size == 10, "analyzer size mismatch");
    require(result.chunkCount == 3, "chunk count mismatch");
    require(result.fullChunksMatchingFirst == 1, "one full repeated chunk expected after first");
    require(result.hasPartialTail, "partial tail should be detected");
    require(result.partialTailMatchesFirstPrefix, "partial tail should match first chunk prefix");
    require(result.zeroBytePercent == 0.0, "zero byte percentage mismatch");
}

void testSignaturesAndZeroFile() {
    const TempFile elf("elf.bin", {0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x08, 0x00});
    const auto elfResult = rth::core::analyzeFile(elf.path(), 16);
    require(elfResult.signature == rth::core::SignatureKind::Elf32LittleEndian, "ELF signature mismatch");
    require(elfResult.signatureDetails.find("MIPS") != std::string::npos, "ELF machine should be reported as MIPS");

    const TempFile zeros("zeros.bin", {0, 0, 0, 0, 0});
    const auto zeroResult = rth::core::analyzeFile(zeros.path(), 4);
    require(zeroResult.signature == rth::core::SignatureKind::AllZero, "zero file should be detected");
    require(zeroResult.zeroBytePercent == 100.0, "all-zero percentage should be 100");
    require(zeroResult.entropyBitsPerByte == 0.0, "all-zero entropy should be 0");
    bool rejectedOversizedChunk = false;
    try { (void)rth::core::analyzeFile(zeros.path(), 65ULL * 1024ULL * 1024ULL); }
    catch (const std::invalid_argument&) { rejectedOversizedChunk = true; }
    require(rejectedOversizedChunk, "excessive chunk size should be rejected safely");
}

void testCompare() {
    const TempFile shortFile("short.bin", {1, 2, 3});
    const TempFile longFile("long.bin", {1, 2, 3, 4});
    const TempFile otherFile("other.bin", {1, 2, 9});
    const auto prefix = rth::core::compareFiles(shortFile.path(), longFile.path(), 2);
    require(prefix.commonPrefixBytes == 3, "prefix length mismatch");
    require(prefix.leftIsPrefixOfRight, "left should be a prefix of right");
    require(!prefix.rightIsPrefixOfLeft, "right should not be a prefix of left");
    const auto mismatch = rth::core::compareFiles(shortFile.path(), otherFile.path(), 2);
    require(mismatch.commonPrefixBytes == 2, "first differing offset mismatch");
    require(!mismatch.leftIsPrefixOfRight && !mismatch.rightIsPrefixOfLeft, "mismatched files are not prefixes");
}

} // namespace

int main() {
    try {
        testEndianReadsAndBounds();
        testRepeatedChunksAndTail();
        testSignaturesAndZeroFile();
        testCompare();
        std::cout << "All rth_core tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return 1;
    }
}
