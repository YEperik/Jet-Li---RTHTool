#!/usr/bin/env python3
"""Validate extracted raw PSX ADPCM streams with FFmpeg's independent decoder.

This is a decoder smoke/integrity check, not a game-format parser. A synthetic WAVE
carrier is used only to packetize the raw bytes on 16-byte frame boundaries. The
selected decoder is forcibly set to FFmpeg's ``adpcm_psx`` decoder; the carrier does
not claim that the game payload is a standard WAV file or IMA ADPCM.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

TOOL_VERSION = "0.1.0"
FRAME_BYTES = 16
SAMPLES_PER_FRAME = 28
BYTES_PER_SAMPLE = 2
WAV_FORMAT_TAG_CARRIER = 0x0011  # WAVE_FORMAT_IMA_ADPCM; decoder is explicitly overridden
CARRIER_SAMPLE_RATE = 32000
CARRIER_BLOCK_ALIGN = FRAME_BYTES
CARRIER_BITS_PER_SAMPLE = 4
CARRIER_SAMPLES_PER_BLOCK = 25  # Carrier metadata only; not used for decoded sample counts.
SYNTHETIC_RESET_FRAME = bytes(FRAME_BYTES)
BATCH_SIZE = 64


class ValidationError(ValueError):
    """Raised for unsupported input, unsafe paths, or invalid validator settings."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_member_name(name: str) -> str:
    """Validate a ZIP member path without extracting it to disk."""
    normalized = name.replace("\\", "/")
    p = PurePosixPath(normalized)
    if (
        not normalized
        or p.is_absolute()
        or not p.parts
        or any(part in ("", ".", "..") for part in p.parts)
        or (p.parts and ":" in p.parts[0])
    ):
        raise ValidationError(f"unsafe archive member path: {name!r}")
    return p.as_posix()


def make_wave_carrier(payload: bytes) -> bytes:
    """Wrap frame-aligned payload in a minimal carrier for FFmpeg packetization.

    The WAV envelope is synthetic: the ``adpcm_psx`` decoder is forced on input.
    The 16-byte WAVE block alignment keeps PSX ADPCM frames intact at demux time.
    """
    if not payload:
        raise ValidationError("payload is empty")
    if len(payload) % FRAME_BYTES:
        raise ValidationError(
            f"payload length {len(payload)} is not a multiple of {FRAME_BYTES} bytes"
        )
    if len(payload) > 0xFFFFFFFF - 64:
        raise ValidationError("payload is too large for a RIFF/WAVE carrier")

    fmt = struct.pack(
        "<HHIIHHH",
        WAV_FORMAT_TAG_CARRIER,
        1,  # mono; observed bank payloads are exported as individual mono streams
        CARRIER_SAMPLE_RATE,
        CARRIER_SAMPLE_RATE * CARRIER_BLOCK_ALIGN // CARRIER_SAMPLES_PER_BLOCK,
        CARRIER_BLOCK_ALIGN,
        CARRIER_BITS_PER_SAMPLE,
        2,  # cbSize
    ) + struct.pack("<H", CARRIER_SAMPLES_PER_BLOCK)
    chunks = (
        b"WAVE"
        + b"fmt " + struct.pack("<I", len(fmt)) + fmt
        + b"data" + struct.pack("<I", len(payload)) + payload
    )
    return b"RIFF" + struct.pack("<I", len(chunks)) + chunks


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def payload_inventory_sha256(payloads: list[tuple[str, bytes]]) -> str:
    """Hash a directory's payload names/hashes deterministically without archiving it."""
    digest = hashlib.sha256()
    for name, payload in sorted(payloads, key=lambda item: item[0]):
        encoded_name = name.encode("utf-8")
        digest.update(struct.pack("<I", len(encoded_name)))
        digest.update(encoded_name)
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def read_payloads(input_path: Path) -> list[tuple[str, bytes]]:
    """Read *.psxadpcm payloads from an extraction folder or extraction ZIP."""
    if input_path.is_dir():
        root = input_path.resolve()
        files = sorted(
            p for p in input_path.rglob("*")
            if p.is_file() and p.suffix.lower() == ".psxadpcm"
        )
        payloads: list[tuple[str, bytes]] = []
        for path in files:
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError) as exc:
                raise ValidationError(f"payload path escapes input directory: {path}") from exc
            payloads.append((path.relative_to(input_path).as_posix(), path.read_bytes()))
        return payloads

    if input_path.is_file() and input_path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(input_path) as archive:
                bad_member = archive.testzip()
                if bad_member is not None:
                    raise ValidationError(f"ZIP CRC test failed for member {bad_member!r}")
                payloads = []
                for info in sorted(archive.infolist(), key=lambda item: item.filename):
                    if info.is_dir() or not info.filename.lower().endswith(".psxadpcm"):
                        continue
                    name = safe_member_name(info.filename)
                    payloads.append((name, archive.read(info.filename)))
                return payloads
        except zipfile.BadZipFile as exc:
            raise ValidationError(f"invalid ZIP archive: {input_path}") from exc

    raise ValidationError("INPUT must be an extracted directory or a ZIP of raw .psxadpcm files")


def select_payloads(
    payloads: list[tuple[str, bytes]], limit: int | None
) -> list[tuple[str, bytes]]:
    """Pick a deterministic, evenly spaced sample; None means every payload."""
    if limit is None or limit >= len(payloads):
        return payloads.copy()
    if limit < 1:
        raise ValidationError("--limit must be at least 1")
    if limit == 1:
        return [payloads[0]]
    indices = [round(i * (len(payloads) - 1) / (limit - 1)) for i in range(limit)]
    return [payloads[i] for i in indices]


def get_ffmpeg_version(ffmpeg_path: str) -> str:
    try:
        result = subprocess.run(
            [ffmpeg_path, "-version"], capture_output=True, text=True, check=False, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(f"could not run FFmpeg at {ffmpeg_path!r}: {exc}") from exc
    if result.returncode != 0:
        raise ValidationError(f"FFmpeg version query failed: {result.stderr[:500]}")
    return result.stdout.splitlines()[0] if result.stdout else "unknown FFmpeg build"


def validate_one(
    item: tuple[str, bytes], ffmpeg_path: str, timeout_seconds: int = 30
) -> dict[str, Any]:
    name, payload = item
    result: dict[str, Any] = {
        "file": name,
        "payload_bytes": len(payload),
        "payload_sha256": sha256_bytes(payload),
        "frame_bytes": FRAME_BYTES,
        "psx_adpcm_frames": len(payload) // FRAME_BYTES,
        "expected_pcm_samples_mono": (len(payload) // FRAME_BYTES) * SAMPLES_PER_FRAME,
        "expected_pcm_bytes_mono_s16le": (len(payload) // FRAME_BYTES) * SAMPLES_PER_FRAME * BYTES_PER_SAMPLE,
        "status": "failed",
    }
    try:
        carrier = make_wave_carrier(payload)
    except ValidationError as exc:
        result["error"] = str(exc)
        return result

    cmd = [
        ffmpeg_path,
        "-nostdin", "-hide_banner", "-loglevel", "error", "-xerror",
        "-ch_layout", "mono", "-c:a", "adpcm_psx",
        "-i", "pipe:0", "-map", "0:a:0", "-f", "s16le", "pipe:1",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=carrier,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        result["error"] = f"FFmpeg timed out after {timeout_seconds} seconds"
        return result
    except OSError as exc:
        result["error"] = f"could not execute FFmpeg: {exc}"
        return result

    result["ffmpeg_returncode"] = proc.returncode
    result["decoded_pcm_bytes"] = len(proc.stdout)
    result["decoded_pcm_sha256"] = sha256_bytes(proc.stdout)
    result["ffmpeg_stderr"] = proc.stderr.decode("utf-8", "replace")[-2000:]
    expected = result["expected_pcm_bytes_mono_s16le"]
    if proc.returncode == 0 and len(proc.stdout) == expected:
        result["status"] = "passed"
    else:
        result["error"] = (
            f"decoder exit={proc.returncode}; decoded {len(proc.stdout)} PCM bytes, expected {expected}"
        )
    return result


def validate_batch(
    items: list[tuple[str, bytes]], ffmpeg_path: str, timeout_seconds: int = 60
) -> list[dict[str, Any]]:
    """Decode a bounded group in one FFmpeg process while resetting ADPCM history.

    A synthetic all-zero PS-ADPCM frame is prepended to each payload. Its filter/shift
    header and nibbles are zero, so FFmpeg should output one silent 28-sample frame and
    reset predictor history. The resulting PCM is split back into per-payload segments.
    This batching avoids thousands of process launches while preserving independently
    reset decoder state at every source-stream boundary.
    """
    records: list[dict[str, Any]] = []
    valid_items: list[tuple[str, bytes, dict[str, Any]]] = []
    for name, payload in items:
        record: dict[str, Any] = {
            "file": name,
            "payload_bytes": len(payload),
            "payload_sha256": sha256_bytes(payload),
            "frame_bytes": FRAME_BYTES,
            "psx_adpcm_frames": len(payload) // FRAME_BYTES,
            "expected_pcm_samples_mono": (len(payload) // FRAME_BYTES) * SAMPLES_PER_FRAME,
            "expected_pcm_bytes_mono_s16le": (len(payload) // FRAME_BYTES) * SAMPLES_PER_FRAME * BYTES_PER_SAMPLE,
            "status": "failed",
        }
        if not payload or len(payload) % FRAME_BYTES:
            record["error"] = f"payload length {len(payload)} is not a non-zero multiple of {FRAME_BYTES} bytes"
            records.append(record)
            continue
        valid_items.append((name, payload, record))
        records.append(record)

    if not valid_items:
        return records

    joined = b"".join(SYNTHETIC_RESET_FRAME + payload for _, payload, _ in valid_items)
    try:
        carrier = make_wave_carrier(joined)
    except ValidationError as exc:
        for _, _, record in valid_items:
            record["error"] = str(exc)
        return records

    cmd = [
        ffmpeg_path,
        "-nostdin", "-hide_banner", "-loglevel", "error", "-xerror",
        "-ch_layout", "mono", "-c:a", "adpcm_psx",
        "-i", "pipe:0", "-map", "0:a:0", "-f", "s16le", "pipe:1",
    ]
    try:
        proc = subprocess.run(
            cmd, input=carrier, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        for _, _, record in valid_items:
            record["error"] = f"FFmpeg batch timed out after {timeout_seconds} seconds"
        return records
    except OSError as exc:
        for _, _, record in valid_items:
            record["error"] = f"could not execute FFmpeg: {exc}"
        return records

    expected_batch_bytes = sum(
        (1 + len(payload) // FRAME_BYTES) * SAMPLES_PER_FRAME * BYTES_PER_SAMPLE
        for _, payload, _ in valid_items
    )
    if proc.returncode != 0 or len(proc.stdout) != expected_batch_bytes:
        error = (
            f"FFmpeg batch exit={proc.returncode}; decoded {len(proc.stdout)} PCM bytes, "
            f"expected {expected_batch_bytes}"
        )
        for _, _, record in valid_items:
            record["ffmpeg_returncode"] = proc.returncode
            record["error"] = error
            record["ffmpeg_stderr"] = proc.stderr.decode("utf-8", "replace")[-2000:]
        return records

    cursor = 0
    reset_pcm_bytes = SAMPLES_PER_FRAME * BYTES_PER_SAMPLE
    for _, payload, record in valid_items:
        reset_pcm = proc.stdout[cursor:cursor + reset_pcm_bytes]
        cursor += reset_pcm_bytes
        output_size = (len(payload) // FRAME_BYTES) * reset_pcm_bytes
        pcm = proc.stdout[cursor:cursor + output_size]
        cursor += output_size
        record["ffmpeg_returncode"] = proc.returncode
        record["decoded_pcm_bytes"] = len(pcm)
        record["decoded_pcm_sha256"] = sha256_bytes(pcm)
        record["boundary_reset_silent"] = reset_pcm == bytes(reset_pcm_bytes)
        record["boundary_reset_pcm_sha256"] = sha256_bytes(reset_pcm)
        record["status"] = (
            "passed"
            if record["boundary_reset_silent"] and len(pcm) == record["expected_pcm_bytes_mono_s16le"]
            else "failed"
        )
        if record["status"] != "passed":
            record["error"] = "synthetic boundary reset frame was not silent or PCM byte count mismatched"
    return records


def validate_collection(
    input_path: Path,
    *,
    ffmpeg: str = "ffmpeg",
    limit: int | None = 64,
    workers: int | None = None,
) -> dict[str, Any]:
    payloads = read_payloads(input_path)
    if not payloads:
        raise ValidationError(f"no .psxadpcm payloads found in {input_path}")
    selected = select_payloads(payloads, limit)
    if input_path.is_file():
        source_kind = "zip_archive"
        source_sha256 = sha256_file(input_path)
        source_inventory_sha256 = None
        source_crc_test = "passed"
    else:
        source_kind = "extraction_directory"
        source_sha256 = None
        source_inventory_sha256 = payload_inventory_sha256(payloads)
        source_crc_test = None
    resolved_ffmpeg = shutil.which(ffmpeg)
    if resolved_ffmpeg is None and Path(ffmpeg).is_file():
        resolved_ffmpeg = str(Path(ffmpeg).resolve())
    if resolved_ffmpeg is None:
        raise ValidationError(f"FFmpeg executable not found: {ffmpeg!r}")
    version = get_ffmpeg_version(resolved_ffmpeg)
    if workers is None:
        workers = min(4, os.cpu_count() or 1)
    if workers < 1 or workers > 64:
        raise ValidationError("--workers must be between 1 and 64")

    started = time.perf_counter()
    if limit is None:
        # One FFmpeg decoder invocation per bounded batch, with a synthetic silent frame
        # before each source stream to clear predictor history. Store a per-stream result.
        records = []
        for start in range(0, len(selected), BATCH_SIZE):
            records.extend(validate_batch(selected[start:start + BATCH_SIZE], resolved_ffmpeg))
        validation_mode = "batched_all_with_per_stream_history_reset"
        batch_count = (len(selected) + BATCH_SIZE - 1) // BATCH_SIZE
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            records = list(pool.map(lambda item: validate_one(item, resolved_ffmpeg), selected))
        validation_mode = "individual_stream_sample"
        batch_count = len(records)
    elapsed = time.perf_counter() - started
    passed = sum(record["status"] == "passed" for record in records)
    failed = len(records) - passed
    summary = {
        "source_payload_count": len(payloads),
        "tested_count": len(records),
        "passed_count": passed,
        "failed_count": failed,
        "coverage_complete": len(records) == len(payloads),
        "selection_mode": "all" if limit is None else "deterministic_even_sample",
        "validation_mode": validation_mode,
        "batch_size": BATCH_SIZE if limit is None else 1,
        "decoder_process_count": batch_count if limit is None else len(records),
        "workers": workers if limit is not None else 1,
        "elapsed_seconds": round(elapsed, 3),
        "status": "passed" if failed == 0 else "failed",
    }
    return {
        "tool": "validate_psxadpcm_ffmpeg.py",
        "tool_version": TOOL_VERSION,
        "engine": "FFmpeg adpcm_psx decoder",
        "ffmpeg_path": resolved_ffmpeg,
        "ffmpeg_version": version,
        "source": input_path.name,
        "source_kind": source_kind,
        "source_sha256": source_sha256,
        "source_crc_test": source_crc_test,
        "payload_inventory_sha256": source_inventory_sha256,
        "method": (
            "Each raw payload is wrapped in a synthetic RIFF carrier with 16-byte block alignment; "
            "FFmpeg's adpcm_psx decoder is forcibly selected. This is a decoder test only, not a claim "
            "that the payload is WAV/IMA ADPCM or that game playback metadata is fully reconstructed."
        ),
        "frame_model": {
            "encoded_bytes_per_frame": FRAME_BYTES,
            "decoded_samples_per_mono_frame": SAMPLES_PER_FRAME,
            "decoded_sample_format": "signed 16-bit little-endian PCM, mono",
        },
        "summary": summary,
        "streams": records,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="extracted directory or ZIP of raw .psxadpcm payloads")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--all", action="store_true", help="decode every discovered .psxadpcm payload")
    selection.add_argument("--limit", type=int, default=64, help="evenly spaced sample size (default: 64)")
    parser.add_argument("--ffmpeg", default="ffmpeg", help="FFmpeg executable path (default: ffmpeg on PATH)")
    parser.add_argument("--workers", type=int, default=None, help="parallel decoder processes (default: up to 8)")
    parser.add_argument("--json-out", type=Path, help="write the full validation report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    limit = None if args.all else args.limit
    try:
        report = validate_collection(
            args.input, ffmpeg=args.ffmpeg, limit=limit, workers=args.workers
        )
    except (ValidationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    if args.json_out:
        print(f"Report: {args.json_out.resolve()}")
    return 0 if report["summary"]["failed_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
