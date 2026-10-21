# RTH Modding Tool

A new, evidence-first PS2 binary research and modding toolkit targeting *Jet Li: Rise to Honor*. This repository was created after the original repository became unavailable. It does **not** claim to recover the old implementation.

## Current scope (0.1.0)

- C++20 core library with a bounds-checked, random-access `BinaryReader`.
- Explicit little-/big-endian integer reads.
- Streaming file inspection: leading signatures, byte entropy, zero-byte percentage, repeated fixed-size blocks, and partial-tail matching.
- Streaming byte-for-byte common-prefix comparison between files.
- CLI hex dump for targeted binary inspection.
- Unit and process-level CLI integration tests via CTest; optional Python helper tests are enabled when a Python interpreter is found. No third-party C++ dependencies.
- Python standard-library tools for ZIP audits, repeat-pattern sweeps across multiple chunk sizes, and reproducible C++ CLI sample runs.

The current analyzer supports a few common leading signatures (ELF and MPEG start codes). It is a research utility, not yet a general PS2 asset parser. Extensions such as `.skx`, `.bnk`, `.ctl`, `.obj`, `.txb`, `.vpk`, and `.wad` are **not** treated as format specifications.

## Build

Requires CMake 3.24+, a C++20 compiler, and optionally Ninja.

Portable build using the platform's default generator:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

With the supplied Ninja preset:

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Debug with ASan/UBSan (where supported):

```sh
cmake --preset sanitizers
cmake --build --preset sanitizers
ctest --preset sanitizers
```

## CLI examples

```sh
rthtool inspect path/to/RTH.skx
rthtool inspect path/to/RTH.skx 0x40000
rthtool compare path/to/unlock0.obj path/to/RTH.skx
rthtool hex path/to/atriumgu.vpk 0 128
```

Sizes and offsets accept decimal or `0x`-prefixed hexadecimal.

## Re-audit the supplied sample ZIP

```sh
python tools/audit_sample_zip.py "path/to/Jet Li - Rise to Honor (USA) (En,Zh).zip" \
  --json-out reports/initial_sample_audit.json \
  --csv-out reports/initial_sample_inventory.csv
```

The ZIP itself is not included in this repository. Keep game dumps and extracted proprietary assets outside Git; use lawful, personally obtained samples. Record SHA-256 hashes and extraction provenance in research logs.

## Reproducible sample analysis

Audit the ZIP and refresh its JSON/CSV/text inventory:

```sh
python tools/audit_sample_zip.py "path/to/sample.zip" \
  --json-out reports/initial_sample_audit.json \
  --csv-out reports/initial_sample_inventory.csv
```

Run the compiled C++ CLI on every file member and save normalized output:

```sh
python tools/run_sample_cli.py "path/to/sample.zip"
```

Investigate whether observed repeated content depends on the chosen chunk size:

```sh
python tools/sweep_sample_chunks.py "path/to/sample.zip"
```

The default sweep sizes are `0x10000`, `0x20000`, `0x40000`, `0x80000`, and `0x100000`. This is an alignment experiment; no chunk size is assumed to be a native game-format boundary.

## Evidence policy

Every format claim should be labeled as confirmed, a supported inference, or a hypothesis. A leading magic value alone does not prove a whole-file format. File extensions alone prove nothing. The default `0x40000` block size is an investigative parameter inherited from the initial sample, **not a known game boundary**.
