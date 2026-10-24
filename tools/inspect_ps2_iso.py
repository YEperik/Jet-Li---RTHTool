#!/usr/bin/env python3
"""Inspect a raw 2048-byte-sector PS2 ISO and identify its BOOT2 executable.

This is a provenance helper, not a proprietary asset parser. It supports the
ISO-9660 primary volume descriptor and ordinary non-interleaved files. Images
using raw 2352-byte sectors, CHD/ZSO, UDF-only layouts, multi-extent files, or
interleaved files are intentionally rejected rather than guessed at.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

SECTOR_SIZE = 2048
PVD_LBA = 16
MAX_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_SYSTEM_CNF_BYTES = 64 * 1024
MAX_BOOT_DEPTH = 32


class IsoProbeError(Exception):
    """Input image or filesystem is not supported or is malformed."""


@dataclass(frozen=True)
class IsoEntry:
    name: str
    extent_lba: int
    size: int
    is_directory: bool
    extended_attribute_length: int = 0
    file_unit_size: int = 0
    interleave_gap_size: int = 0
    multi_extent: bool = False

    @property
    def data_offset(self) -> int:
        return (self.extent_lba + self.extended_attribute_length) * SECTOR_SIZE

    @property
    def lookup_name(self) -> str:
        return strip_version(self.name).casefold()


def strip_version(name: str) -> str:
    return re.sub(r";[0-9]+$", "", name)


def read_exact(stream: BinaryIO, offset: int, count: int, image_size: int, label: str) -> bytes:
    if offset < 0 or count < 0 or offset > image_size or count > image_size - offset:
        raise IsoProbeError(f"{label} lies outside image bounds (offset={offset}, size={count})")
    stream.seek(offset)
    data = stream.read(count)
    if len(data) != count:
        raise IsoProbeError(f"short read for {label}: expected {count}, got {len(data)}")
    return data


def both_endian_u16(record: bytes, offset: int, field: str) -> int:
    if offset + 4 > len(record):
        raise IsoProbeError(f"truncated {field} field")
    little = int.from_bytes(record[offset:offset + 2], "little")
    big = int.from_bytes(record[offset + 2:offset + 4], "big")
    if little != big:
        raise IsoProbeError(f"inconsistent both-endian ISO field: {field}")
    return little


def both_endian_u32(record: bytes, offset: int, field: str) -> int:
    if offset + 8 > len(record):
        raise IsoProbeError(f"truncated {field} field")
    little = int.from_bytes(record[offset:offset + 4], "little")
    big = int.from_bytes(record[offset + 4:offset + 8], "big")
    if little != big:
        raise IsoProbeError(f"inconsistent both-endian ISO field: {field}")
    return little


def parse_directory_record(record: bytes, *, include_special: bool = False) -> IsoEntry | None:
    if len(record) < 34:
        raise IsoProbeError("directory record shorter than ISO-9660 minimum")
    record_length = record[0]
    if record_length != len(record):
        raise IsoProbeError("directory record length mismatch")
    identifier_length = record[32]
    identifier_start = 33
    identifier_end = identifier_start + identifier_length
    if identifier_end > len(record) or identifier_length == 0:
        raise IsoProbeError("invalid ISO directory identifier length")
    if identifier_length % 2 == 0 and identifier_end >= len(record):
        raise IsoProbeError("missing ISO directory identifier padding")

    identifier = record[identifier_start:identifier_end]
    if identifier in (b"\x00", b"\x01"):
        if not include_special:
            return None  # Current and parent directory entries.
        name = "." if identifier == b"\x00" else ".."
    else:
        try:
            name = identifier.decode("ascii")
        except UnicodeDecodeError:
            name = identifier.decode("latin-1")

    flags = record[25]
    return IsoEntry(
        name=name,
        extent_lba=both_endian_u32(record, 2, "extent location"),
        size=both_endian_u32(record, 10, "data length"),
        is_directory=bool(flags & 0x02),
        extended_attribute_length=record[1],
        file_unit_size=record[26],
        interleave_gap_size=record[27],
        multi_extent=bool(flags & 0x80),
    )


def make_iso_directory_record(
    *, name: bytes, extent_lba: int, size: int, flags: int = 0, extended_attribute_length: int = 0
) -> bytes:
    """Build a standard ISO-9660 directory record for test fixtures."""
    identifier_length = len(name)
    padding = b"\x00" if identifier_length % 2 == 0 else b""
    record_length = 33 + identifier_length + len(padding)
    record = bytearray(record_length)
    record[0] = record_length
    record[1] = extended_attribute_length
    record[2:10] = extent_lba.to_bytes(4, "little") + extent_lba.to_bytes(4, "big")
    record[10:18] = size.to_bytes(4, "little") + size.to_bytes(4, "big")
    record[18:25] = bytes((126, 1, 1, 0, 0, 0, 0))
    record[25] = flags
    record[26] = 0
    record[27] = 0
    record[28:32] = (1).to_bytes(2, "little") + (1).to_bytes(2, "big")
    record[32] = identifier_length
    record[33:33 + identifier_length] = name
    if padding:
        record[-1] = 0
    return bytes(record)


class Iso9660Image:
    def __init__(self, path: Path):
        self.path = path
        self.stream = path.open("rb")
        self.image_size = path.stat().st_size
        self.volume_space_size = 0
        self.declared_volume_size = 0
        self.volume_id = ""
        self.logical_block_size = 0
        self.root: IsoEntry | None = None
        try:
            self._read_primary_volume_descriptor()
        except Exception:
            self.stream.close()
            raise

    def __enter__(self) -> "Iso9660Image":
        return self

    def __exit__(self, *_: object) -> None:
        self.stream.close()

    def read_at(self, offset: int, count: int, label: str) -> bytes:
        return read_exact(self.stream, offset, count, self.image_size, label)

    def _read_primary_volume_descriptor(self) -> None:
        if self.image_size < (PVD_LBA + 1) * SECTOR_SIZE:
            raise IsoProbeError("image is too small to contain ISO-9660 volume descriptors")

        found_pvd = False
        for lba in range(PVD_LBA, min(PVD_LBA + 256, self.image_size // SECTOR_SIZE)):
            descriptor = self.read_at(lba * SECTOR_SIZE, SECTOR_SIZE, f"volume descriptor at LBA {lba}")
            if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
                raise IsoProbeError(f"invalid ISO-9660 descriptor signature/version at LBA {lba}")
            descriptor_type = descriptor[0]
            if descriptor_type == 1 and not found_pvd:
                found_pvd = True
                self.volume_id = descriptor[40:72].decode("ascii", errors="replace").strip()
                self.volume_space_size = both_endian_u32(descriptor, 80, "volume space size")
                self.logical_block_size = both_endian_u16(descriptor, 128, "logical block size")
                if self.logical_block_size != SECTOR_SIZE:
                    raise IsoProbeError(
                        f"unsupported logical block size {self.logical_block_size}; expected {SECTOR_SIZE}"
                    )
                root_record_length = descriptor[156]
                if root_record_length < 34 or 156 + root_record_length > len(descriptor):
                    raise IsoProbeError("invalid root directory record in primary volume descriptor")
                self.root = parse_directory_record(descriptor[156:156 + root_record_length], include_special=True)
                if self.root is None or not self.root.is_directory:
                    raise IsoProbeError("primary volume descriptor root record is not a directory")
            if descriptor_type == 255:
                break
        if not found_pvd or self.root is None:
            raise IsoProbeError("no valid ISO-9660 primary volume descriptor found")
        declared_size = self.volume_space_size * self.logical_block_size
        if self.volume_space_size <= 0:
            raise IsoProbeError("ISO volume space size is zero")
        self.declared_volume_size = declared_size
        if declared_size > self.image_size:
            raise IsoProbeError(
                f"image shorter than declared ISO volume ({self.image_size} bytes < {declared_size} bytes)"
            )

    def read_entry(self, entry: IsoEntry, *, maximum: int | None = None) -> bytes:
        self._validate_regular_entry(entry)
        if maximum is not None and entry.size > maximum:
            raise IsoProbeError(f"{entry.name} is {entry.size} bytes; safety limit is {maximum} bytes")
        return self.read_at(entry.data_offset, entry.size, entry.name)

    def _validate_regular_entry(self, entry: IsoEntry) -> None:
        if entry.is_directory:
            raise IsoProbeError(f"{entry.name} is a directory, not a regular file")
        if entry.multi_extent:
            raise IsoProbeError(f"multi-extent files are not supported: {entry.name}")
        if entry.file_unit_size or entry.interleave_gap_size:
            raise IsoProbeError(f"interleaved files are not supported: {entry.name}")
        if (entry.size < 0 or entry.data_offset > self.image_size or entry.size > self.image_size - entry.data_offset
                or entry.data_offset > self.declared_volume_size
                or entry.size > self.declared_volume_size - entry.data_offset):
            raise IsoProbeError(f"file extent is outside image/volume bounds: {entry.name}")

    def directory_entries(self, directory: IsoEntry) -> list[IsoEntry]:
        if not directory.is_directory:
            raise IsoProbeError(f"{directory.name} is not a directory")
        if directory.multi_extent or directory.file_unit_size or directory.interleave_gap_size:
            raise IsoProbeError(f"unsupported directory extent layout: {directory.name}")
        if directory.size > MAX_DIRECTORY_BYTES:
            raise IsoProbeError(f"directory exceeds {MAX_DIRECTORY_BYTES}-byte safety limit")
        if (directory.data_offset > self.image_size or directory.size > self.image_size - directory.data_offset
                or directory.data_offset > self.declared_volume_size
                or directory.size > self.declared_volume_size - directory.data_offset):
            raise IsoProbeError(f"directory lies outside image/volume bounds: {directory.name}")
        data = self.read_at(directory.data_offset, directory.size, f"directory {directory.name}")
        found: list[IsoEntry] = []
        position = 0
        while position < len(data):
            sector_offset = position % SECTOR_SIZE
            length = data[position]
            if length == 0:
                position += SECTOR_SIZE - sector_offset
                continue
            if length < 34 or position + length > len(data):
                raise IsoProbeError(f"malformed directory record at byte offset {position}")
            if sector_offset + length > SECTOR_SIZE:
                raise IsoProbeError(f"directory record crosses a logical sector at byte offset {position}")
            entry = parse_directory_record(data[position:position + length])
            if entry is not None:
                found.append(entry)
            position += length
        return found

    def find_path(self, parts: list[str]) -> IsoEntry:
        if self.root is None:
            raise IsoProbeError("ISO root directory unavailable")
        if not parts:
            raise IsoProbeError("empty path is not a file path")
        if len(parts) > MAX_BOOT_DEPTH:
            raise IsoProbeError("BOOT2 path exceeds maximum directory depth")
        for part in parts:
            if part in (".", "..") or ":" in part:
                raise IsoProbeError(f"unsafe or unsupported component in BOOT2 path: {part!r}")

        current = self.root
        for index, part in enumerate(parts):
            matches = [entry for entry in self.directory_entries(current) if entry.lookup_name == strip_version(part).casefold()]
            if len(matches) != 1:
                reason = "not found" if not matches else "ambiguous"
                raise IsoProbeError(f"BOOT2 path component {part!r} {reason} in {current.name}")
            current = matches[0]
            is_last = index == len(parts) - 1
            if not is_last and not current.is_directory:
                raise IsoProbeError(f"BOOT2 path component is not a directory: {current.name}")
        if current.is_directory:
            raise IsoProbeError("BOOT2 resolves to a directory, not an executable file")
        return current


def parse_boot2(system_cnf: bytes) -> str:
    text = system_cnf.decode("ascii", errors="replace")
    for line in text.splitlines():
        match = re.match(r"^\s*BOOT2\s*=\s*(.*?)\s*$", line, re.IGNORECASE)
        if match:
            value = match.group(1).strip().strip('"')
            if not value:
                raise IsoProbeError("SYSTEM.CNF contains an empty BOOT2 value")
            return value
    raise IsoProbeError("SYSTEM.CNF has no BOOT2= line")


def boot_path_parts(boot_value: str) -> list[str]:
    value = boot_value.strip()
    if ":" in value:
        device, _, rest = value.partition(":")
        if not device or any(ch.isspace() for ch in device):
            raise IsoProbeError(f"unsupported BOOT2 device prefix: {device!r}")
        value = rest
    value = value.replace("\\", "/")
    parts = [part for part in value.split("/") if part]
    if not parts:
        raise IsoProbeError(f"BOOT2 value does not contain an ISO path: {boot_value!r}")
    if any(part in (".", "..") for part in parts):
        raise IsoProbeError(f"BOOT2 path contains traversal components: {boot_value!r}")
    return parts


def iso_sha256(image: Iso9660Image) -> str:
    image.stream.seek(0)
    digest = hashlib.sha256()
    while True:
        block = image.stream.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
    image.stream.seek(0)
    return digest.hexdigest()


def analyze_elf_header(image: Iso9660Image, executable: IsoEntry) -> dict[str, object]:
    header = image.read_at(executable.data_offset, min(executable.size, 64), "boot executable header")
    is_elf = header.startswith(b"\x7fELF")
    info: dict[str, object] = {"is_elf": is_elf, "magic_hex": header[:4].hex(" ")}
    if not is_elf:
        return info
    if len(header) < 20:
        info["header_complete"] = False
        return info
    elf_class = {1: "ELF32", 2: "ELF64"}.get(header[4], f"unknown({header[4]})")
    elf_data = {1: "little-endian", 2: "big-endian"}.get(header[5], f"unknown({header[5]})")
    info["class"] = elf_class
    info["endianness"] = elf_data
    if header[5] == 1:
        info["machine"] = int.from_bytes(header[18:20], "little")
    elif header[5] == 2:
        info["machine"] = int.from_bytes(header[18:20], "big")
    else:
        info["machine"] = None
    return info


def executable_digests(image: Iso9660Image, executable: IsoEntry, boot_value: str) -> dict[str, object]:
    image._validate_regular_entry(executable)
    sha = hashlib.sha256()
    ra_prefix = boot_value.encode("ascii", errors="replace")
    ra_md5 = hashlib.md5()
    ra_md5.update(ra_prefix)
    xor_crc = 0
    image.stream.seek(executable.data_offset)
    remaining = executable.size
    pending = b""
    while remaining:
        block = image.stream.read(min(1024 * 1024, remaining))
        if not block:
            raise IsoProbeError("short read while hashing the BOOT2 executable")
        remaining -= len(block)
        sha.update(block)
        ra_md5.update(block)
        block = pending + block
        aligned = len(block) - (len(block) % 4)
        for offset in range(0, aligned, 4):
            xor_crc ^= int.from_bytes(block[offset:offset + 4], "little")
        pending = block[aligned:]
    image.stream.seek(0)

    variants: list[dict[str, str]] = []
    # The public RA description specifies an executable path/name followed by
    # the executable bytes. Keep path-string variants explicit because the
    # exact normalization is not described on the documentation page.
    path_only = boot_value.partition(":")[2] if ":" in boot_value else boot_value
    path_only = path_only.replace("/", "\\")
    variants.append({"prefix_kind": "BOOT2 value as written", "md5": ra_md5.hexdigest(), "prefix_text": boot_value})
    if path_only != boot_value:
        variants.append({
            "prefix_kind": "BOOT2 path without device prefix",
            "md5": md5_with_prefix_and_entry(image, executable, path_only),
            "prefix_text": path_only,
        })
    without_leading_separator = path_only.lstrip("\\/")
    if without_leading_separator and without_leading_separator != path_only:
        variants.append({
            "prefix_kind": "ISO-relative path without leading separator",
            "md5": md5_with_prefix_and_entry(image, executable, without_leading_separator),
            "prefix_text": without_leading_separator,
        })

    return {
        "size": executable.size,
        "sha256": sha.hexdigest(),
        "pcsx2_style_xor_crc32": f"{xor_crc:08x}",
        "pcsx2_crc_word_count": executable.size // 4,
        "pcsx2_crc_ignored_tail_bytes": executable.size % 4,
        "retroachievements_md5_candidates": variants,
    }


def md5_with_prefix_and_entry(image: Iso9660Image, executable: IsoEntry, prefix: str) -> str:
    digest = hashlib.md5()
    digest.update(prefix.encode("ascii", errors="replace"))
    image.stream.seek(executable.data_offset)
    remaining = executable.size
    while remaining:
        block = image.stream.read(min(1024 * 1024, remaining))
        if not block:
            raise IsoProbeError("short read while calculating alternate identification hash")
        digest.update(block)
        remaining -= len(block)
    image.stream.seek(0)
    return digest.hexdigest()


def inspect_iso(path: Path, expected_ra_hash: str | None = None) -> dict[str, object]:
    if not path.is_file():
        raise IsoProbeError(f"image does not exist or is not a regular file: {path}")
    with Iso9660Image(path) as image:
        root_entries = image.directory_entries(image.root)  # type: ignore[arg-type]
        system_matches = [entry for entry in root_entries if entry.lookup_name == "system.cnf"]
        if len(system_matches) != 1:
            reason = "not found" if not system_matches else "ambiguous"
            raise IsoProbeError(f"root SYSTEM.CNF {reason}")
        system_entry = system_matches[0]
        system_bytes = image.read_entry(system_entry, maximum=MAX_SYSTEM_CNF_BYTES)
        boot_value = parse_boot2(system_bytes)
        boot_parts = boot_path_parts(boot_value)
        executable = image.find_path(boot_parts)
        digests = executable_digests(image, executable, boot_value)
        candidate_rows = digests["retroachievements_md5_candidates"]
        assert isinstance(candidate_rows, list)
        normalized_expected = expected_ra_hash.lower() if expected_ra_hash else None
        matched = [row for row in candidate_rows if normalized_expected and row["md5"].lower() == normalized_expected]

        return {
            "image": str(path),
            "image_size": image.image_size,
            "image_sha256": iso_sha256(image),
            "iso9660": {
                "volume_id": image.volume_id,
                "logical_block_size": image.logical_block_size,
                "volume_space_size_sectors": image.volume_space_size,
                "declared_volume_size": image.volume_space_size * image.logical_block_size,
            },
            "system_cnf": {
                "iso_name": system_entry.name,
                "size": len(system_bytes),
                "sha256": hashlib.sha256(system_bytes).hexdigest(),
                "boot2_value": boot_value,
            },
            "boot_executable": {
                "iso_path": str(PurePosixPath(*boot_parts)),
                "iso_name": executable.name,
                **analyze_elf_header(image, executable),
                **digests,
            },
            "expected_retroachievements_hash": normalized_expected,
            "expected_hash_matched_candidate_kinds": [row["prefix_kind"] for row in matched],
            "hash_notes": [
                "The full-image SHA-256 fingerprints this image file; it is not the game identity hash.",
                "pcsx2_style_xor_crc32 is the XOR of little-endian 32-bit executable words; it is not standard CRC-32.",
                "RetroAchievements candidates use MD5 over a BOOT2 path/name prefix plus executable bytes. Variants are emitted for diagnostics because path normalization is not fully specified by the public high-level description.",
            ],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso_path", type=Path, help="raw 2048-byte-sector ISO image")
    parser.add_argument("--expected-ra-hash", help="optional expected RetroAchievements hash to compare")
    parser.add_argument("--json-out", type=Path, help="write the full report as JSON")
    args = parser.parse_args(argv)

    if args.expected_ra_hash and not re.fullmatch(r"[0-9a-fA-F]{32}", args.expected_ra_hash):
        parser.error("--expected-ra-hash must be a 32-character hexadecimal MD5 value")
    try:
        report = inspect_iso(args.iso_path, args.expected_ra_hash)
        print(f"Image: {report['image']}")
        print(f"Image size: {report['image_size']:,} bytes")
        print(f"Image SHA-256: {report['image_sha256']}")
        iso_meta = report["iso9660"]
        cnf = report["system_cnf"]
        boot = report["boot_executable"]
        print(f"ISO volume ID: {iso_meta['volume_id']!r}; declared size: {iso_meta['declared_volume_size']:,} bytes")
        print(f"SYSTEM.CNF: {cnf['iso_name']} ({cnf['size']:,} bytes; SHA-256 {cnf['sha256']})")
        print(f"BOOT2: {cnf['boot2_value']}")
        print(f"Executable: {boot['iso_path']} ({boot['size']:,} bytes; SHA-256 {boot['sha256']})")
        print(f"ELF: {boot['is_elf']}; class={boot.get('class', 'unknown')}; endian={boot.get('endianness', 'unknown')}; machine={boot.get('machine')}")
        print(f"PCSX2-style XOR CRC: {boot['pcsx2_style_xor_crc32']} ({boot['pcsx2_crc_word_count']:,} words)")
        print("RetroAchievements MD5 candidates (path normalization variants):")
        for row in boot["retroachievements_md5_candidates"]:
            print(f"  {row['prefix_kind']}: {row['md5']}  [prefix={row['prefix_text']!r}]")
        if args.expected_ra_hash:
            print(f"Expected RA hash: {args.expected_ra_hash.lower()}")
            print(f"Matching candidate variants: {report['expected_hash_matched_candidate_kinds'] or 'none'}")
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f"JSON report: {args.json_out}")
    except (OSError, IsoProbeError) as exc:
        print(f"ISO probe error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
