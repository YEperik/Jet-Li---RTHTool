#!/usr/bin/env python3
"""Test whether repeated byte patterns persist across several chunk sizes.

This is an alignment experiment, not a claim that any chunk size corresponds to
an actual proprietary format boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import zipfile
from collections import Counter
from pathlib import Path
from typing import BinaryIO


def parse_size(value: str) -> int:
    try:
        size = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid chunk size: {value}") from error
    if size <= 0 or size > 64 * 1024 * 1024:
        raise argparse.ArgumentTypeError("chunk size must be in range 1..64 MiB")
    return size


def read_up_to(stream: BinaryIO, limit: int) -> bytes:
    data = bytearray()
    while len(data) < limit:
        part = stream.read(limit - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def shortest_proper_period(hashes: list[str]) -> int | None:
    """Return the shortest repeat period in chunk-hash count, or None."""
    if len(hashes) < 2:
        return None
    for period in range(1, len(hashes)):
        if all(value == hashes[index % period] for index, value in enumerate(hashes)):
            return period
    return None


def summarize_member(bundle: zipfile.ZipFile, entry: zipfile.ZipInfo, chunk_size: int) -> dict[str, int | str | None]:
    full_hashes: list[str] = []
    tail_size = 0
    with bundle.open(entry, "r") as stream:
        while True:
            chunk = read_up_to(stream, chunk_size)
            if not chunk:
                break
            digest = hashlib.sha256(chunk).hexdigest()
            if len(chunk) == chunk_size:
                full_hashes.append(digest)
            else:
                tail_size = len(chunk)
                break

    counts = Counter(full_hashes)
    first_hash_matches = max(0, counts[full_hashes[0]] - 1) if full_hashes else 0
    return {
        "name": entry.filename,
        "size": entry.file_size,
        "full_chunks": len(full_hashes),
        "unique_full_hashes": len(counts),
        "matches_first_after_first": first_hash_matches,
        "proper_period_chunks": shortest_proper_period(full_hashes),
        "tail_bytes": tail_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path)
    parser.add_argument(
        "--chunk-sizes", nargs="+", type=parse_size,
        default=[0x10000, 0x20000, 0x40000, 0x80000, 0x100000],
        help="sizes as decimal or hexadecimal (default: 0x10000 0x20000 0x40000 0x80000 0x100000)",
    )
    parser.add_argument(
        "--report", type=Path,
        default=Path(__file__).resolve().parents[1] / "reports" / "chunk_size_sweep.txt",
    )
    args = parser.parse_args()
    archive = args.zip_path.resolve()
    if not archive.is_file():
        parser.error(f"ZIP does not exist or is not a file: {archive}")

    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)

    lines = [
        "RTH Modding Tool — fixed-chunk alignment sweep",
        f"Archive: {archive.name}",
        f"Archive SHA-256: {digest.hexdigest()}",
        "Purpose: test repeated-content periodicity at candidate chunk sizes.",
        "Caution: periodicity is an observation about these bytes, not a format specification.",
        "",
    ]

    try:
        with zipfile.ZipFile(archive, "r") as bundle:
            bad_member = bundle.testzip()
            if bad_member is not None:
                raise RuntimeError(f"ZIP CRC failure in member: {bad_member}")
            entries = sorted((e for e in bundle.infolist() if not e.is_dir()), key=lambda e: e.filename)
            lines.append("ZIP CRC test: PASS")
            lines.append(f"File members: {len(entries)}")
            for chunk_size in sorted(set(args.chunk_sizes)):
                lines.extend([
                    "",
                    f"## Chunk size 0x{chunk_size:x} ({chunk_size:,} bytes)",
                    "file | size | full chunks | unique full-chunk hashes | first-hash matches after first | shortest proper period (chunks) | tail bytes",
                    "--- | ---: | ---: | ---: | ---: | ---: | ---:",
                ])
                for entry in entries:
                    result = summarize_member(bundle, entry, chunk_size)
                    period = result["proper_period_chunks"]
                    period_text = str(period) if period is not None else "none observed"
                    lines.append(
                        f"{result['name']} | {result['size']} | {result['full_chunks']} | "
                        f"{result['unique_full_hashes']} | {result['matches_first_after_first']} | "
                        f"{period_text} | {result['tail_bytes']}"
                    )
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        print(f"error: {error}")
        return 1

    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote report: {report}")
    print(f"Chunk sizes tested: {', '.join(hex(x) for x in sorted(set(args.chunk_sizes)))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
