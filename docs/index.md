# Digital Archaeologist

**Read-only** binary archaeology for files, disk images, archives, firmware blobs, databases, executables, and unknown data. Extension-independent, signed-release CLI, one static binary per OS.

```text
archaeologist suspicious.bin
archaeologist --json suspicious.bin
archaeologist --carve ./out firmware.img
archaeologist --timeline report.pdf
archaeologist --scan /mnt/evidence
```

## What makes it different

- **Over 70 formats** detected by signature — executables, images, audio/video, archives, filesystems, firmware, game ROMs, crypto keys, scientific data, network captures.
- **Evidence-scored confidence.** Weak magics (TTF's `00 01 00 00`, pickle opcodes) are reported with weighted evidence, not as if they were as certain as `%PDF-`.
- **Streaming hashes.** SHA-256 always covers the whole file, even when structural analysis is capped with `--max-size` to protect against hostile inputs.
- **Carving without decompression.** `--carve` finds embedded streams by signature and writes each to its own file — forensic-safe, nothing is interpreted.
- **Format-aware timeline.** `--timeline` reads DOS mtimes out of ZIP local headers, `TimeDateStamp` out of PE/COFF, `/CreationDate` and `/ModDate` out of PDF dictionaries.
- **Read-only by design.** No mounting. No driver installation. No writes to the input. Ever.

## Install

See [Install](INSTALL.md). Static binaries are published on the Releases page for Linux, macOS, and Windows.

## Build from source

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Requires CMake 3.20, a C++17 compiler, and nothing else.

## Quick reference

See [CLI reference](CLI.md) for every flag, [Features](FEATURES.md) for the full capability list, and [Format catalog](formats.md) for exactly which signatures are detected and at what confidence.
