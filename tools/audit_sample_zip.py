#!/usr/bin/env python3
"""Reproducibly audit a ZIP containing extracted PS2 game samples.

Uses only the Python standard library. The default 0x40000 chunk size is an
investigative lens carried forward from the supplied sample; it is not asserted
to be a game-format boundary.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_CHUNK_SIZE = 0x40000


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def common_prefix_length(left: bytes, right: bytes) -> int:
    limit = min(len(left), len(right))
    offset = 0
    while offset < limit and left[offset] == right[offset]:
        offset += 1
    return offset


def classify(data: bytes) -> str:
    if not data:
        return "empty"
    if data.startswith(b"\x7fELF"):
        return "ELF-like header"
    if data.startswith(b"\x00\x00\x01\xba"):
        return "MPEG pack start code"
    if data.startswith(b"\x00\x00\x01\xbb"):
        return "MPEG system-header start code"
    if data.startswith(b"\x00\x00\x01\xb9"):
        return "MPEG end-code-like prefix (file type unconfirmed)"
    if not any(data):
        return "all-zero"
    return "unclassified leading signature"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    value = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return 0.0 if value == 0.0 else value


def audit_member(name: str, data: bytes, crc: int, chunk_size: int) -> dict[str, Any]:
    chunks = [data[offset:offset + chunk_size] for offset in range(0, len(data), chunk_size)]
    chunk_hashes = [sha256(chunk) for chunk in chunks]
    full_chunk_count = len(data) // chunk_size
    remainder = len(data) % chunk_size
    full_hashes = chunk_hashes[:full_chunk_count]
    matches_after_first = 0
    if full_hashes:
        first_hash = full_hashes[0]
        matches_after_first = sum(1 for digest in full_hashes[1:] if digest == first_hash)

    tail_match: bool | None = None
    if len(data) > chunk_size and remainder:
        tail_match = data[full_chunk_count * chunk_size:] == data[:remainder]

    return {
        "name": name,
        "size": len(data),
        "crc32": f"{crc:08x}",
        "sha256": sha256(data),
        "signature": classify(data[:64]),
        "first_32_bytes_hex": data[:32].hex(" "),
        "zero_bytes": data.count(0),
        "zero_percent": (100.0 * data.count(0) / len(data)) if data else 0.0,
        "shannon_entropy_bits_per_byte": entropy(data),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "unique_chunk_sha256_count": len(set(chunk_hashes)),
        "full_chunks_after_first_matching_first": matches_after_first,
        "full_chunk_count": full_chunk_count,
        "partial_tail_exists_after_full_chunk": len(data) > chunk_size and remainder != 0,
        "partial_tail_matches_prefix_of_first_chunk": tail_match,
        "_data": data,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path)
    parser.add_argument("--chunk-size", type=lambda value: int(value, 0), default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--json-out", type=Path, help="also write machine-readable JSON")
    parser.add_argument("--csv-out", type=Path, help="also write machine-readable CSV")
    args = parser.parse_args()

    if args.chunk_size <= 0 or args.chunk_size > 64 * 1024 * 1024:
        parser.error("--chunk-size must be between 1 and 64 MiB")
    if not args.zip_path.is_file():
        parser.error(f"ZIP does not exist: {args.zip_path}")

    try:
        with zipfile.ZipFile(args.zip_path) as archive:
            bad_member = archive.testzip()
            crc_status = "PASS" if bad_member is None else f"FAIL ({bad_member})"
            rows = []
            content_by_name: dict[str, bytes] = {}
            for info in archive.infolist():
                if info.is_dir():
                    continue
                data = archive.read(info.filename)
                content_by_name[info.filename] = data
                row = audit_member(info.filename, data, info.CRC, args.chunk_size)
                rows.append(row)

        pairs: list[dict[str, Any]] = []
        names = list(content_by_name)
        for index, left_name in enumerate(names):
            for right_name in names[index + 1:]:
                left, right = content_by_name[left_name], content_by_name[right_name]
                prefix_length = common_prefix_length(left, right)
                if prefix_length >= 16 or (prefix_length == min(len(left), len(right)) and prefix_length > 0):
                    pairs.append({
                        "left": left_name,
                        "right": right_name,
                        "common_prefix_bytes": prefix_length,
                        "shorter_is_exact_prefix": prefix_length == min(len(left), len(right)),
                        "identical_content": len(left) == len(right) == prefix_length,
                    })

        report = {
            "archive": str(args.zip_path),
            "archive_size": args.zip_path.stat().st_size,
            "archive_sha256": file_sha256(args.zip_path),
            "zip_crc_test": crc_status,
            "chunk_size": args.chunk_size,
            "member_count": len(rows),
            "members": [{key: value for key, value in row.items() if key != "_data"} for row in rows],
            "common_prefix_relationships": pairs,
        }

        print(f"Archive: {args.zip_path}")
        print(f"Archive size: {report['archive_size']:,} bytes")
        print(f"Archive SHA-256: {report['archive_sha256']}")
        print(f"ZIP CRC test: {crc_status}")
        print(f"Chunk size: 0x{args.chunk_size:X} ({args.chunk_size:,} bytes)")
        print(f"Members: {len(rows)}\n")
        for row in rows:
            print(f"[{row['name']}]")
            print(f"  size: {row['size']:,}; CRC-32: {row['crc32']}; SHA-256: {row['sha256']}")
            print(f"  signature: {row['signature']}")
            print(f"  first bytes: {row['first_32_bytes_hex']}")
            print(f"  zero bytes: {row['zero_percent']:.2f}%; entropy: {row['shannon_entropy_bits_per_byte']:.4f} bits/byte")
            print(f"  chunks: {row['chunk_count']}; unique SHA-256 chunk hashes: {row['unique_chunk_sha256_count']}")
            print(f"  full chunks after first matching first: {row['full_chunks_after_first_matching_first']} / {max(0, row['full_chunk_count'] - 1)}")
            print(f"  partial tail matches first-chunk prefix: {row['partial_tail_matches_prefix_of_first_chunk']}")
        print("\nCommon-prefix relationships:")
        for pair in pairs:
            if pair["shorter_is_exact_prefix"]:
                print(f"  {pair['left']} / {pair['right']}: shorter is exact prefix ({pair['common_prefix_bytes']:,} bytes)")
            else:
                print(f"  {pair['left']} / {pair['right']}: common prefix {pair['common_prefix_bytes']:,} bytes")

        serializable_rows = [{key: value for key, value in row.items() if key != "_data"} for row in rows]
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if args.csv_out:
            args.csv_out.parent.mkdir(parents=True, exist_ok=True)
            fieldnames = list(serializable_rows[0].keys()) if serializable_rows else []
            with args.csv_out.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(serializable_rows)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"audit error: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
