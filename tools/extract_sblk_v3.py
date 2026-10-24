#!/usr/bin/env python3
"""Inspect and conservatively extract raw stream payloads from Sony SBlk v3 BNK samples.

This is an evidence-first extractor, not a general BNK decoder. It handles the SBlk
version-3 table layout observed in the supplied Jet Li: Rise to Honor BNK archive.
It writes raw stream payloads plus a JSON manifest; it does not decode audio to WAV.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import struct
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SBLK_OFFSET = 0x18
SBLK_VERSION = 3
DESCRIPTOR_SIZE = 0x18
STREAM_REF_SUBTYPE = 0x0100
PSX_FRAME_SIZE = 0x10
PSX_END_FRAMES = {
    bytes.fromhex("00 07 77 77 77 77 77 77"),
    bytes.fromhex("00 07 00 00 00 00 00 00"),
}


class BnkFormatError(ValueError):
    """Raised when a bank cannot be safely interpreted as this SBlk v3 variant."""


def u16le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise BnkFormatError(f"u16 read out of range at 0x{offset:x}")
    return struct.unpack_from("<H", data, offset)[0]


def u32le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise BnkFormatError(f"u32 read out of range at 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative_path(value: str) -> Path:
    """Convert an archive member path to a safe relative filesystem path."""
    normalized = value.replace("\\", "/")
    p = PurePosixPath(normalized)
    if not normalized or not p.parts or p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        raise BnkFormatError(f"unsafe archive member path: {value!r}")
    if re.match(r"^[A-Za-z]:", normalized):
        raise BnkFormatError(f"drive-qualified archive member path is not allowed: {value!r}")
    return Path(*p.parts)


@dataclass
class Descriptor:
    grain_index: int
    descriptor_offset: int
    stream_offset: int
    declared_size: int
    stream_flags: int
    raw_header_hex: str


@dataclass
class BankParse:
    source_name: str
    size: int
    sha256: str
    outer_version: int
    container_kind: int
    header_size_value: int
    metadata_marker: int
    data_offset: int
    data_size: int
    sblk_version: int
    sound_count: int
    grain_count: int
    wave_count: int
    table1_offset: int
    table2_offset: int
    table3_offset: int
    table4_offset: int | None
    table3_limit: int
    table2_type_counts: dict[str, int] = field(default_factory=dict)
    descriptors: list[Descriptor] = field(default_factory=list)
    streams: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "file_size": self.size,
            "sha256": self.sha256,
            "format_candidate": "Sony 989SND/SCREAM BNK family; SBlk version 3 (supported inference)",
            "header": {
                "outer_version": self.outer_version,
                "container_kind": self.container_kind,
                "header_size_value": self.header_size_value,
                "metadata_marker": self.metadata_marker,
                "data_offset": self.data_offset,
                "data_size": self.data_size,
                "sblk_offset": SBLK_OFFSET,
                "sblk_version": self.sblk_version,
                "sound_count": self.sound_count,
                "grain_count": self.grain_count,
                "wave_count": self.wave_count,
                "table1_offset": self.table1_offset,
                "table2_offset": self.table2_offset,
                "table3_offset": self.table3_offset,
                "table4_offset": self.table4_offset,
                "table3_limit": self.table3_limit,
            },
            "table2_type_counts": self.table2_type_counts,
            "descriptor_reference_count": int(self.table2_type_counts.get("0x0100", 0)),
            "valid_descriptor_count": len(self.descriptors),
            "invalid_descriptor_reference_count": int(self.table2_type_counts.get("0x0100", 0)) - len(self.descriptors),
            "unique_stream_count": len(self.streams),
            "descriptors": [
                {
                    "grain_index": d.grain_index,
                    "descriptor_offset": d.descriptor_offset,
                    "stream_offset": d.stream_offset,
                    "declared_size": d.declared_size,
                    "stream_flags": d.stream_flags,
                    "raw_header_hex": d.raw_header_hex,
                }
                for d in self.descriptors
            ],
            "streams": self.streams,
            "warnings": self.warnings,
        }


def _parse_one(data: bytes, source_name: str) -> BankParse:
    if len(data) < 0x20:
        raise BnkFormatError(f"{source_name}: file too short for outer header/SBlk")

    outer_version = u32le(data, 0x00)
    container_kind = u32le(data, 0x04)
    header_size_value = u32le(data, 0x08)
    metadata_marker = u32le(data, 0x0C)
    data_offset = u32le(data, 0x10)
    data_size = u32le(data, 0x14)

    if data[SBLK_OFFSET:SBLK_OFFSET + 4] != b"SBlk":
        raise BnkFormatError(f"{source_name}: SBlk signature not found at 0x18")
    sblk_version = u32le(data, SBLK_OFFSET + 4)
    if sblk_version != SBLK_VERSION:
        raise BnkFormatError(f"{source_name}: unsupported SBlk version {sblk_version}; only v3 is handled")
    if outer_version != 3 or container_kind != 2 or header_size_value != SBLK_OFFSET:
        raise BnkFormatError(
            f"{source_name}: outer header differs from the observed v3 variant "
            f"(version={outer_version}, kind={container_kind}, header-size={header_size_value})"
        )
    if metadata_marker + SBLK_OFFSET != data_offset:
        raise BnkFormatError(
            f"{source_name}: metadata marker/data offset relationship failed "
            f"({metadata_marker:#x} + 0x18 != {data_offset:#x})"
        )
    if data_offset > len(data) or data_size > len(data) - data_offset or data_offset + data_size != len(data):
        raise BnkFormatError(
            f"{source_name}: payload range does not end at file size "
            f"(data_offset={data_offset:#x}, data_size={data_size:#x}, file_size={len(data):#x})"
        )

    sound_count = u16le(data, SBLK_OFFSET + 0x16)
    grain_count = u16le(data, SBLK_OFFSET + 0x18)
    wave_count = u16le(data, SBLK_OFFSET + 0x1A)
    table1_offset = SBLK_OFFSET + u32le(data, SBLK_OFFSET + 0x1C)
    table2_offset = SBLK_OFFSET + u32le(data, SBLK_OFFSET + 0x20)
    table3_offset = SBLK_OFFSET + u32le(data, SBLK_OFFSET + 0x34)
    table4_rel = u32le(data, SBLK_OFFSET + 0x38)
    table4_offset = SBLK_OFFSET + table4_rel if table4_rel else None

    metadata_limit = data_offset
    for label, offset in (("table1", table1_offset), ("table2", table2_offset), ("table3", table3_offset)):
        if offset < SBLK_OFFSET + 8 or offset > metadata_limit:
            raise BnkFormatError(f"{source_name}: {label} offset out of metadata bounds: {offset:#x}")
    table1_end = table1_offset + sound_count * 0x0C
    table2_end = table2_offset + grain_count * 0x08
    if table1_end != table2_offset:
        raise BnkFormatError(
            f"{source_name}: table1 extent mismatch ({table1_offset:#x} + {sound_count}*0xc != {table2_offset:#x})"
        )
    if table2_end != table3_offset:
        raise BnkFormatError(
            f"{source_name}: table2 extent mismatch ({table2_offset:#x} + {grain_count}*8 != {table3_offset:#x})"
        )
    if table1_end > metadata_limit or table2_end > metadata_limit:
        raise BnkFormatError(f"{source_name}: table extent exceeds metadata boundary")

    warnings: list[str] = []
    if table4_offset is not None:
        if table4_offset <= table3_offset or table4_offset > metadata_limit:
            warnings.append(
                f"table4 pointer {table4_offset:#x} is outside expected range; descriptor area capped at data offset"
            )
            table4_limit: int | None = None
        else:
            table4_limit = table4_offset
    else:
        table4_limit = None
    table3_limit = table4_limit if table4_limit is not None else data_offset
    if table3_offset > table3_limit:
        raise BnkFormatError(f"{source_name}: table3 has an invalid boundary")

    type_counts: collections.Counter[int] = collections.Counter()
    descriptors: list[Descriptor] = []
    invalid_references: list[str] = []
    for grain_index in range(grain_count):
        row = table2_offset + grain_index * 8
        packed = u32le(data, row)
        subtype = (packed >> 16) & 0xFFFF
        subinfo = packed & 0xFFFF
        type_counts[subtype] += 1
        if subtype != STREAM_REF_SUBTYPE:
            continue
        descriptor_offset = table3_offset + subinfo
        if descriptor_offset < table3_offset or descriptor_offset + DESCRIPTOR_SIZE > table3_limit:
            invalid_references.append(
                f"grain {grain_index}: subtype 0x0100 refers to descriptor {descriptor_offset:#x}, "
                f"outside table3 descriptor boundary ending at {table3_limit:#x}"
            )
            continue
        stream_offset = u32le(data, descriptor_offset + 0x10)
        declared_size = u32le(data, descriptor_offset + 0x14)
        stream_flags = u16le(data, descriptor_offset + 0x0E)
        descriptors.append(
            Descriptor(
                grain_index=grain_index,
                descriptor_offset=descriptor_offset,
                stream_offset=stream_offset,
                declared_size=declared_size,
                stream_flags=stream_flags,
                raw_header_hex=data[descriptor_offset:descriptor_offset + DESCRIPTOR_SIZE].hex(),
            )
        )
    warnings.extend(invalid_references)

    # Group all references to the same payload start. The data offset is relative to the
    # outer header's data section, while descriptor offsets are absolute in the BNK.
    by_start: dict[int, list[Descriptor]] = {}
    for desc in descriptors:
        if desc.stream_offset > data_size:
            warnings.append(
                f"descriptor at {desc.descriptor_offset:#x}: stream offset {desc.stream_offset:#x} exceeds data size {data_size:#x}"
            )
            continue
        by_start.setdefault(desc.stream_offset, []).append(desc)

    starts = sorted(by_start)
    streams: list[dict[str, Any]] = []
    for stream_index, start in enumerate(starts, start=1):
        refs = by_start[start]
        next_start = next((candidate for candidate in starts if candidate > start), None)
        bound_end = next_start if next_start is not None else data_size
        available = bound_end - start
        flags_set = sorted({d.stream_flags for d in refs})
        codec_set = sorted({"pcm16" if (d.stream_flags & 0x80) else "psx_adpcm" for d in refs})
        size_set = sorted({d.declared_size for d in refs if d.declared_size > 0})
        declared_size = size_set[0] if len(size_set) == 1 else 0
        size_conflict = len(size_set) > 1
        if size_conflict:
            warnings.append(
                f"stream at data+{start:#x}: conflicting declared sizes {size_set}; size not trusted"
            )

        status = "unresolved"
        length_method = "unresolved"
        exact_size: int | None = None
        candidate_size: int | None = None
        note: str | None = None
        if start == data_size:
            note = "stream offset points to end of data section"
        elif declared_size and not size_conflict:
            if declared_size <= available and start + declared_size <= data_size:
                exact_size = declared_size
                candidate_size = declared_size
                length_method = "declared_size"
                status = "exact"
            elif start + declared_size <= data_size:
                # Explicit size is in the data region but crosses the next payload start;
                # preserve the evidence as a warning but do not extract by default.
                candidate_size = declared_size
                length_method = "declared_size_overlaps_next_stream"
                status = "conflict"
                note = "declared size crosses a later distinct stream start"
            else:
                status = "invalid"
                note = "declared size extends beyond the bank data section"
        elif size_conflict:
            status = "conflict"
            note = "conflicting descriptor lengths"
        else:
            is_pcm = "pcm16" in codec_set
            if len(codec_set) > 1:
                status = "conflict"
                note = "references disagree on PCM16 versus PSX ADPCM flag"
            elif is_pcm:
                # PCM payloads have no PS-ADPCM end marker; only a next-offset estimate is possible.
                candidate_size = available if available > 0 and available % 2 == 0 else None
                length_method = "next_stream_offset_inferred" if candidate_size else "unresolved"
                status = "inferred" if candidate_size else "unresolved"
                note = "size field is zero; PCM16 length has no supported terminator in this tool"
            else:
                scanned_size, scanned_method = scan_psx_adpcm_frames(data, data_offset + start, available)
                if scanned_size is not None:
                    exact_size = scanned_size
                    candidate_size = scanned_size
                    length_method = scanned_method
                    status = "exact"
                else:
                    candidate_size = available if available > 0 and available % PSX_FRAME_SIZE == 0 else None
                    length_method = "next_stream_offset_inferred" if candidate_size else "unresolved"
                    status = "inferred" if candidate_size else "unresolved"
                    note = "no recognized PS-ADPCM end/zero frame before the next stream boundary"

        ext = ".bin"
        if len(codec_set) == 1:
            ext = ".pcm16" if codec_set[0] == "pcm16" else ".psxadpcm"
        rel_output = f"stream_{stream_index:04d}{ext}"
        streams.append(
            {
                "stream_index": stream_index,
                "data_offset": start,
                "file_offset": data_offset + start,
                "next_stream_offset": next_start,
                "available_until_next_offset": available,
                "descriptor_offsets": sorted({d.descriptor_offset for d in refs}),
                "grain_indices": sorted({d.grain_index for d in refs}),
                "reference_count": len(refs),
                "stream_flags": flags_set,
                "codec_candidate": codec_set[0] if len(codec_set) == 1 else "conflicting_or_unknown",
                "declared_sizes": sorted({d.declared_size for d in refs}),
                "length_method": length_method,
                "status": status,
                "exact_size": exact_size,
                "candidate_size": candidate_size,
                "extract_by_default": status == "exact" and exact_size is not None,
                "output_name": rel_output,
                "note": note,
            }
        )

    return BankParse(
        source_name=source_name,
        size=len(data),
        sha256=sha256_bytes(data),
        outer_version=outer_version,
        container_kind=container_kind,
        header_size_value=header_size_value,
        metadata_marker=metadata_marker,
        data_offset=data_offset,
        data_size=data_size,
        sblk_version=sblk_version,
        sound_count=sound_count,
        grain_count=grain_count,
        wave_count=wave_count,
        table1_offset=table1_offset,
        table2_offset=table2_offset,
        table3_offset=table3_offset,
        table4_offset=table4_offset,
        table3_limit=table3_limit,
        table2_type_counts={f"0x{k:04x}": v for k, v in sorted(type_counts.items())},
        descriptors=descriptors,
        streams=streams,
        warnings=warnings,
    )


def scan_psx_adpcm_frames(data: bytes, absolute_start: int, maximum_bytes: int) -> tuple[int | None, str]:
    """Detect vgmstream's v3 PS-ADPCM terminators within a conservative next-stream bound.

    The returned exact length includes an end-marked frame and excludes an all-zero
    sentinel frame. A missing marker returns (None, 'unresolved').
    """
    if maximum_bytes < PSX_FRAME_SIZE or absolute_start < 0 or absolute_start + maximum_bytes > len(data):
        return None, "unresolved"
    length = PSX_FRAME_SIZE
    pos = absolute_start + PSX_FRAME_SIZE
    end = absolute_start + maximum_bytes
    while pos + PSX_FRAME_SIZE <= end:
        frame = data[pos:pos + PSX_FRAME_SIZE]
        if frame == b"\x00" * PSX_FRAME_SIZE:
            return length, "zero_frame_terminator"
        length += PSX_FRAME_SIZE
        first_eight = frame[:8]
        if first_eight in PSX_END_FRAMES:
            return length, "psx_adpcm_terminal_frame"
        pos += PSX_FRAME_SIZE
    return None, "unresolved"


def load_banks(input_path: Path, members: Iterable[str] | None = None) -> tuple[list[tuple[str, bytes]], dict[str, Any]]:
    wanted = set(members or [])
    if input_path.suffix.lower() == ".bnk":
        if wanted:
            raise BnkFormatError("--member can only be used when INPUT is a ZIP archive")
        raw = input_path.read_bytes()
        return [(input_path.name, raw)], {
            "source_type": "bnk_file",
            "source_path": str(input_path),
            "source_sha256": sha256_bytes(raw),
            "archive_crc_test": None,
        }
    if input_path.suffix.lower() != ".zip":
        raise BnkFormatError("INPUT must be a .bnk file or a .zip containing BNK members")
    archive_bytes = input_path.read_bytes()
    source_hash = sha256_bytes(archive_bytes)
    with zipfile.ZipFile(input_path) as archive:
        bad_member = archive.testzip()
        if bad_member is not None:
            raise BnkFormatError(f"ZIP CRC test failed for member {bad_member!r}")
        selected: list[tuple[str, bytes]] = []
        available = {info.filename for info in archive.infolist() if not info.is_dir() and info.filename.lower().endswith(".bnk")}
        for requested in wanted:
            if requested not in available:
                raise BnkFormatError(f"requested BNK member not found in ZIP: {requested!r}")
        names = sorted(available if not wanted else wanted)
        for name in names:
            safe_relative_path(name)
            selected.append((name, archive.read(name)))
    return selected, {
        "source_type": "zip_archive",
        "source_path": input_path.name,
        "source_size": len(archive_bytes),
        "source_sha256": source_hash,
        "archive_crc_test": "passed",
        "bnk_member_count_in_archive": len(available),
    }


def inspect_banks(input_path: Path, members: Iterable[str] | None = None) -> dict[str, Any]:
    blobs, source = load_banks(input_path, members)
    parsed: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for name, data in blobs:
        try:
            parsed.append(_parse_one(data, name).to_json())
        except BnkFormatError as exc:
            errors.append({"source_name": name, "error": str(exc), "file_size": len(data), "sha256": sha256_bytes(data)})
    summary = summarize_banks(parsed, errors)
    return {
        "tool": "extract_sblk_v3.py",
        "tool_version": "0.1.0",
        "source": source,
        "scope": "SBlk version 3 variant observed in the supplied Jet Li BNK ZIP; not a general BNK parser",
        "reference": "https://github.com/vgmstream/vgmstream/blob/master/src/meta/bnk_sony.c",
        "summary": summary,
        "banks": parsed,
        "parse_errors": errors,
    }


def summarize_banks(banks: list[dict[str, Any]], errors: list[dict[str, str]]) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    total_refs = 0
    total_streams = 0
    exact_streams = inferred_streams = unresolved_streams = conflict_streams = 0
    invalid_refs = 0
    for bank in banks:
        total_refs += bank["descriptor_reference_count"]
        total_streams += bank["unique_stream_count"]
        invalid_refs += bank["invalid_descriptor_reference_count"]
        for stream in bank["streams"]:
            status = stream["status"]
            status_counts[status] = status_counts.get(status, 0) + 1
            if status == "exact":
                exact_streams += 1
            elif status == "inferred":
                inferred_streams += 1
            elif status == "conflict":
                conflict_streams += 1
            else:
                unresolved_streams += 1
    return {
        "bank_count_requested": len(banks) + len(errors),
        "bank_count_parsed": len(banks),
        "bank_count_parse_error": len(errors),
        "descriptor_references_total": total_refs,
        "valid_descriptor_references": sum(bank["valid_descriptor_count"] for bank in banks),
        "unique_stream_offsets": total_streams,
        "stream_status_counts": dict(sorted(status_counts.items())),
        "exact_streams": exact_streams,
        "inferred_streams": inferred_streams,
        "unresolved_streams": unresolved_streams,
        "conflict_streams": conflict_streams,
        "invalid_descriptor_references": invalid_refs,
        "warning_count": sum(len(bank["warnings"]) for bank in banks),
    }


def resolve_inside(root: Path, relative: Path) -> Path:
    root_resolved = root.resolve()
    output = (root / relative).resolve()
    if output != root_resolved and root_resolved not in output.parents:
        raise BnkFormatError(f"refusing output path outside output directory: {relative}")
    return output


def extract_banks(
    input_path: Path,
    out_dir: Path,
    members: Iterable[str] | None = None,
    include_inferred: bool = False,
) -> dict[str, Any]:
    blobs, source = load_banks(input_path, members)
    output_root = out_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    bank_records: list[dict[str, Any]] = []
    written_files: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for member_name, data in blobs:
        try:
            parsed = _parse_one(data, member_name)
            bank_rel = safe_relative_path(member_name) if source["source_type"] == "zip_archive" else Path(Path(member_name).name)
            bank_folder = bank_rel.parent / bank_rel.stem
            written_streams: list[dict[str, Any]] = []
            for stream in parsed.streams:
                length = stream["exact_size"]
                is_inferred = False
                if length is None and include_inferred and stream["candidate_size"] is not None and stream["status"] == "inferred":
                    length = stream["candidate_size"]
                    is_inferred = True
                if length is None:
                    continue
                if length <= 0:
                    continue
                start = parsed.data_offset + stream["data_offset"]
                end = start + length
                if start < parsed.data_offset or end > parsed.data_offset + parsed.data_size or end > len(data):
                    stream["extraction_error"] = "computed range outside data section; not written"
                    continue
                output_rel = bank_folder / stream["output_name"]
                output_path = resolve_inside(output_root, output_rel)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                payload = data[start:end]
                output_path.write_bytes(payload)
                file_info = {
                    "source_member": member_name,
                    "output_path": output_rel.as_posix(),
                    "stream_index": stream["stream_index"],
                    "data_offset": stream["data_offset"],
                    "source_file_offset": start,
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                    "length_method": stream["length_method"],
                    "inferred": is_inferred,
                    "codec_candidate": stream["codec_candidate"],
                }
                written_files.append(file_info)
                written_streams.append(file_info)
            bank_records.append(
                {
                    "source_name": parsed.source_name,
                    "source_size": parsed.size,
                    "source_sha256": parsed.sha256,
                    "metadata": parsed.to_json(),
                    "written_stream_count": len(written_streams),
                    "written_streams": written_streams,
                }
            )
        except (BnkFormatError, OSError) as exc:
            errors.append({"source_name": member_name, "error": str(exc)})

    manifest = {
        "tool": "extract_sblk_v3.py",
        "tool_version": "0.1.0",
        "operation": "extract_raw_payloads",
        "source": source,
        "output_policy": {
            "default": "only declared-size or recognized PS-ADPCM-terminator payload lengths are written",
            "include_inferred": include_inferred,
            "raw_payloads_only": True,
            "decoded_audio_output": False,
        },
        "summary": {
            "bank_count_requested": len(blobs),
            "bank_count_parsed": len(bank_records),
            "bank_count_parse_error": len(errors),
            "written_stream_count": len(written_files),
            "written_bytes": sum(f["size"] for f in written_files),
            "inferred_streams_written": sum(bool(f["inferred"]) for f in written_files),
            "errors": len(errors),
        },
        "banks": bank_records,
        "written_files": written_files,
        "errors": errors,
    }
    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_extraction(input_path: Path, out_dir: Path, manifest_path: Path | None = None) -> dict[str, Any]:
    """Verify every manifest-listed output against the original source member byte range."""
    output_root = out_dir.resolve()
    manifest_file = manifest_path or (output_root / "manifest.json")
    if not manifest_file.is_file():
        raise BnkFormatError(f"manifest not found: {manifest_file}")
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BnkFormatError(f"could not read manifest {manifest_file}: {exc}") from exc
    if not isinstance(manifest, dict) or "source" not in manifest or "written_files" not in manifest or "banks" not in manifest:
        raise BnkFormatError("manifest does not have the expected extraction schema")

    bank_names = sorted({str(bank["source_name"]) for bank in manifest["banks"]})
    if input_path.suffix.lower() == ".zip":
        blobs, source_info = load_banks(input_path, bank_names)
    else:
        blobs, source_info = load_banks(input_path)
    expected_source = manifest["source"]
    if source_info.get("source_type") != expected_source.get("source_type"):
        raise BnkFormatError("source kind does not match the extraction manifest")
    if source_info.get("source_sha256") != expected_source.get("source_sha256"):
        raise BnkFormatError("source SHA-256 differs from the extraction manifest")

    bank_data = {name: data for name, data in blobs}
    parsed_banks: dict[str, BankParse] = {}
    for name, data in blobs:
        parsed_banks[name] = _parse_one(data, name)

    errors: list[str] = []
    verified = 0
    verified_bytes = 0
    terminal_markers = 0
    zero_sentinels = 0
    for record in manifest["written_files"]:
        member = str(record.get("source_member", ""))
        data = bank_data.get(member)
        if data is None:
            errors.append(f"source member absent from current source: {member!r}")
            continue
        try:
            rel = safe_relative_path(str(record["output_path"]))
            file_path = resolve_inside(output_root, rel)
            payload = file_path.read_bytes()
        except (KeyError, OSError, BnkFormatError) as exc:
            errors.append(f"{record.get('output_path', '<missing path>')}: {exc}")
            continue
        start = int(record.get("source_file_offset", -1))
        size = int(record.get("size", -1))
        bank = parsed_banks[member]
        relative_start = int(record.get("data_offset", -1))
        if start != bank.data_offset + relative_start:
            errors.append(f"{rel}: manifest file offset does not match bank data offset + relative stream offset")
            continue
        if size <= 0 or start < bank.data_offset or start + size > bank.data_offset + bank.data_size:
            errors.append(f"{rel}: manifest byte range falls outside the source data section")
            continue
        expected_payload = data[start:start + size]
        if payload != expected_payload:
            errors.append(f"{rel}: extracted bytes differ from the source bank byte range")
            continue
        digest = sha256_bytes(payload)
        if digest != record.get("sha256"):
            errors.append(f"{rel}: payload SHA-256 does not match manifest")
            continue
        method = record.get("length_method")
        if method == "psx_adpcm_terminal_frame":
            if len(payload) < PSX_FRAME_SIZE or payload[-PSX_FRAME_SIZE:-8] not in PSX_END_FRAMES:
                errors.append(f"{rel}: terminal-frame method is inconsistent with final frame bytes")
                continue
            terminal_markers += 1
        elif method == "zero_frame_terminator":
            if data[start + size:start + size + PSX_FRAME_SIZE] != b"\x00" * PSX_FRAME_SIZE:
                errors.append(f"{rel}: zero-frame boundary is not followed by a full zero frame")
                continue
            zero_sentinels += 1
        verified += 1
        verified_bytes += size

    return {
        "tool": "extract_sblk_v3.py",
        "operation": "verify_extraction_manifest",
        "source_path": input_path.name,
        "source_sha256": source_info.get("source_sha256"),
        "manifest_path": manifest_file.name,
        "files_listed": len(manifest["written_files"]),
        "files_verified": verified,
        "bytes_verified": verified_bytes,
        "psx_adpcm_terminal_frames_verified": terminal_markers,
        "zero_frame_sentinels_verified": zero_sentinels,
        "error_count": len(errors),
        "errors": errors,
        "status": "passed" if not errors and verified == len(manifest["written_files"]) else "failed",
    }


def write_json(path: Path | None, obj: dict[str, Any]) -> None:
    payload = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(payload, end="")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "extract"):
        cmd = sub.add_parser(command, help=f"{command} SBlk v3 BNK file(s)")
        cmd.add_argument("input", type=Path, help="one .bnk file or a ZIP containing .bnk members")
        cmd.add_argument("--member", action="append", default=[], help="select exact ZIP member path; may be repeated")
        if command == "inspect":
            cmd.add_argument("--json-out", type=Path, help="write JSON report to this path")
        else:
            cmd.add_argument("--out-dir", type=Path, required=True, help="directory for raw payloads and manifest.json")
            cmd.add_argument("--include-inferred", action="store_true", help="also write lengths inferred from the next stream offset")
    verify_cmd = sub.add_parser("verify", help="verify extracted files against source byte ranges and manifest hashes")
    verify_cmd.add_argument("input", type=Path, help="the original .bnk file or source ZIP")
    verify_cmd.add_argument("--out-dir", type=Path, required=True, help="extraction output directory")
    verify_cmd.add_argument("--manifest", type=Path, help="manifest path (default: OUT_DIR/manifest.json)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify":
            report = verify_extraction(args.input, args.out_dir, args.manifest)
            write_json(None, report)
            return 0 if report["status"] == "passed" else 1
        if args.command == "inspect":
            report = inspect_banks(args.input, args.member)
            write_json(args.json_out, report)
            summary = report["summary"]
            print(
                f"Inspected {summary['bank_count_parsed']}/{summary['bank_count_requested']} banks; "
                f"{summary['unique_stream_offsets']} unique payload starts; "
                f"{summary['exact_streams']} exact, {summary['inferred_streams']} inferred, "
                f"{summary['unresolved_streams']} unresolved; {summary['bank_count_parse_error']} parse errors",
                file=sys.stderr,
            )
            return 0 if summary["bank_count_parse_error"] == 0 else 2
        manifest = extract_banks(args.input, args.out_dir, args.member, args.include_inferred)
        print(json.dumps(manifest["summary"], indent=2, sort_keys=True))
        print(f"Manifest: {args.out_dir.resolve() / 'manifest.json'}")
        return 0 if manifest["summary"]["bank_count_parse_error"] == 0 else 2
    except (BnkFormatError, OSError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
