#!/usr/bin/env python3
"""Run the C++ inspection CLI over every file in a ZIP and save a stable report.

Extraction is temporary and path-validated. This tool records observations about
bytes currently inside the supplied archive; it does not validate proprietary
format claims or the provenance of those bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative_path(name: str) -> Path:
    """Reject archive member names that could escape the temporary root."""
    if not name or "\\" in name:
        raise ValueError(f"Unsafe ZIP member path: {name!r}")
    posix = PurePosixPath(name)
    if posix.is_absolute() or any(part in ("", ".", "..") for part in posix.parts):
        raise ValueError(f"Unsafe ZIP member path: {name!r}")
    if posix.parts and ":" in posix.parts[0]:
        raise ValueError(f"Drive-like ZIP member path is not accepted: {name!r}")
    return Path(*posix.parts)


def run_cli(tool: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(tool), *args],
        check=False,
        capture_output=True,
        text=True,
        errors="replace",
    )


def require_cli_success(result: subprocess.CompletedProcess[str], command: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(
            f"rthtool command failed ({result.returncode}): {command}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path, help="ZIP containing extracted game samples")
    parser.add_argument(
        "--rthtool",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "build" / "rthtool",
        help="path to the compiled rthtool executable",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "reports" / "cpp_sample_runs.txt",
        help="output report path",
    )
    parser.add_argument(
        "--chunk-size",
        default="0x40000",
        help="inspection chunk size (decimal or 0x-prefixed hexadecimal; default 0x40000)",
    )
    args = parser.parse_args()

    archive = args.zip_path.resolve()
    tool = args.rthtool.resolve()
    report = args.report.resolve()
    try:
        chunk_size = int(args.chunk_size, 0)
    except ValueError:
        parser.error("--chunk-size must be decimal or 0x-prefixed hexadecimal")
    if chunk_size <= 0:
        parser.error("--chunk-size must be positive")
    if not archive.is_file():
        parser.error(f"ZIP does not exist or is not a file: {archive}")
    if not tool.is_file():
        parser.error(f"rthtool executable does not exist: {tool}")

    archive_digest = sha256_file(archive)
    try:
        with zipfile.ZipFile(archive, "r") as bundle:
            bad_member = bundle.testzip()
            if bad_member is not None:
                raise RuntimeError(f"ZIP CRC failure in member: {bad_member}")

            entries = sorted(
                (entry for entry in bundle.infolist() if not entry.is_dir()),
                key=lambda entry: entry.filename,
            )
            if not entries:
                raise RuntimeError("ZIP contains no file entries")

            lines: list[str] = [
                "RTH Modding Tool — C++ sample CLI run",
                f"Archive: {archive.name}",
                f"Archive size: {archive.stat().st_size} bytes",
                f"Archive SHA-256: {archive_digest}",
                "ZIP CRC test: PASS",
                f"Members: {len(entries)}",
                f"Inspection chunk size: {chunk_size} bytes (0x{chunk_size:x})",
                "",
            ]

            with tempfile.TemporaryDirectory(prefix="rth-cli-samples-") as temp_name:
                temp_root = Path(temp_name)
                extracted: list[tuple[str, Path]] = []
                for index, entry in enumerate(entries):
                    relative = safe_relative_path(entry.filename)
                    destination = temp_root / str(index) / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(entry, "r") as source, destination.open("wb") as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                    extracted.append((entry.filename, destination))

                for name, path in extracted:
                    result = run_cli(tool, "inspect", str(path), hex(chunk_size))
                    require_cli_success(result, f"inspect {name} {hex(chunk_size)}")
                    normalized = result.stdout.replace(
                        f"File: {path}\n", f"File: {name}\n", 1
                    )
                    lines.append(f"## {name}")
                    lines.append(normalized.rstrip())
                    lines.append("")

                lines.append("## Exact prefix relationships reported by rthtool")
                prefix_count = 0
                for left_index, (left_name, left_path) in enumerate(extracted):
                    for right_name, right_path in extracted[left_index + 1 :]:
                        result = run_cli(tool, "compare", str(left_path), str(right_path))
                        require_cli_success(result, f"compare {left_name} {right_name}")
                        common_line = next(
                            (line.strip() for line in result.stdout.splitlines()
                             if line.startswith("Common prefix:")),
                            "Common prefix: unavailable",
                        )
                        left_prefix = "Left is a prefix of right: yes" in result.stdout
                        right_prefix = "Right is a prefix of left: yes" in result.stdout
                        if left_prefix or right_prefix:
                            if left_prefix and right_prefix:
                                relation = "byte-identical"
                            elif left_prefix:
                                relation = "left is prefix of right"
                            else:
                                relation = "right is prefix of left"
                            lines.append(
                                f"- {left_name} / {right_name}: {relation}; {common_line}"
                            )
                            prefix_count += 1
                if prefix_count == 0:
                    lines.append("No exact-prefix relationships detected.")

                elf_candidate = next(
                    ((name, path) for name, path in extracted if path.suffix.lower() == ".vpk"),
                    None,
                )
                if elf_candidate is not None:
                    name, path = elf_candidate
                    result = run_cli(tool, "hex", str(path), "0", "64")
                    require_cli_success(result, f"hex {name} 0 64")
                    hex_output = result.stdout.replace(
                        f"Hex dump: {path} @", f"Hex dump: {name} @", 1
                    )
                    lines.extend(["", f"## Hex dump smoke test — {name}", hex_output.rstrip()])

        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"Wrote report: {report}")
    print(f"Archive SHA-256: {archive_digest}")
    print(f"Members inspected: {len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
