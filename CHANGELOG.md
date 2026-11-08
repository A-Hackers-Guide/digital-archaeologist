# Changelog

All notable changes to Digital Archaeologist. Dates are UTC; versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added

- **Container walk** (`da::list_container`): reads ZIP / TAR / GZIP indexes without decompressing. New `--list` CLI flag. 10 000-entry cap per listing with a `truncated` flag so a hostile archive can't DoS the walker.
- **30+ new detection signatures**: SQLite WAL + rollback journal, Redis RDB, Lua bytecode, QEMU QED, VirtualBox VDI, N64 ROM, Switch NSP (PFS0) + XCI, Xbox XBE, Xbox 360 XEX2, PSX EXE, Bethesda ESM/ESP + BSA, SoundFont 2, DTS, AC-3, glTF, Apache Avro, Windows EVTX + crash dumps, Apple LZFSE, xar, ARJ, LHA, JPEG XR, Photoshop PSB, Fujifilm RAF, EDID monitor descriptors, IDA Pro database, Bitcoin mainnet blocks, VCDIFF, OpenDocument (ODT/ODS/ODP via ZIP inner mimetype).
- **Benchmark suite** (`bench/`) behind `-DDA_BENCH=ON`. Three binaries for `analyze_bytes`, `sha256`, `carve`. Zero third-party deps. See [Benchmarks](docs/benchmarks.md).

## [2.2.0] — 2026-11-08

### Added

- **Streaming SHA-256** (`include/hashing.hpp`): hashes files chunk-by-chunk so the whole file is covered even when structural analysis is capped.
- **Streaming CRC-32** (`include/crc32.hpp`, flag `--crc32`): IEEE 802.3 / zlib / PNG polynomial.
- **UTF-16LE string extraction** (`include/strings_ex.hpp`): one-pass scan returns both ASCII and UTF-16LE hits with offset + encoding. Flags: `--ascii-only`, `--utf16-only`.
- **`--carve DIR`** (`include/carve.hpp`): signature-based carving of 14 file types out of a blob.
- **`--timeline`** (`include/timeline.hpp`): filesystem mtime + ZIP DOS mtime + PE/COFF `TimeDateStamp` + GZIP member mtime + PDF `/CreationDate` / `/ModDate`.
- **`--max-size BYTES`**: cap in-memory structural analysis (default 2 GiB). SHA-256 still streams the whole file.
- **`--mime`**: print the best-guess MIME and exit.
- **50+ new detection signatures**, bringing the catalog to 70+ formats. Highlights: TIFF, WebP, HEIF/HEIC, AVIF, PSD, OpenEXR, ICO/CUR, JPEG XL, HDF5, TTF/OTF/WOFF/WOFF2, FLAC, Ogg, MIDI, AIFF, AU, Matroska/WebM, FLV, AVI, LZ4, Zstandard, CAB, RPM, DEB, ar, CFBF/OLE, PostScript, CHM, RTF, XML, WebAssembly, Dalvik DEX, Android boot/sparse/backup, DTB, iNES, Doom WAD, Quake PAK, Blizzard MPQ, XFS, F2FS, btrfs, QCOW2, VMDK, VHD, libpcap LE+BE, PCAPNG, Chrome CRX, PEM/OpenSSH/PGP/OpenSSL `Salted__`, NumPy, Parquet, Arrow IPC, Python pickle, shebang.
- **ISOBMFF brand dispatcher**: one `ftyp` lookup resolves MP4 / M4A / M4V / M4B / MOV / HEIF / AVIF / 3GP / 3GPP2 / Canon CR3 and more.
- **`da::analyze_bytes`** public API for in-memory analysis (no tmp-file round-trip for fuzzers and tests).
- **`da::print_report_json`**: documented JSON schema.
- **`tests/`** directory with 7 C++ test drivers (detect, sha256, base64, crc32, strings, carve, timeline) + 4 CLI smokes. 11 CTest cases, all green on Linux/macOS/Windows.
- **libFuzzer targets** (`fuzz/analyze_fuzz.cpp`, `fuzz/carve_fuzz.cpp`) behind `-DDA_FUZZ=ON`.
- **`.github/workflows/sanitize.yml`**: ASan + UBSan on every PR, plus 60-second libFuzzer runs on both targets.
- **`.github/workflows/docs.yml`**: mkdocs-material strict build + GitHub Pages deploy.
- **`docs/index.md`**, **`docs/formats.md`**, **`docs/json-schema.md`**: new documentation pages.

### Changed

- **Rewrote `src/main.cpp`** as a readable ~340-line dispatcher. Previous version was one golfed file with hundreds of statements per line.
- **Wired `src/analyzer.cpp` / `include/analyzer.hpp` into the build.** The clean `da::Report` / `Detection` / `Evidence` module was previously dead code; the built binary now delegates to it.
- **`da_core` static library**: analyzer + base64 + carve + crc32 + hashing + strings + timeline, linked by both the CLI and the test drivers.
- **`--find` / `--find-hex`** now report every match offset instead of just the first.
- **`--strings`** output now carries `<encoding>@<offset>: <text>` and scans ASCII + UTF-16LE in one pass.

### Fixed

- **HFS+ detection** was matching `"H+H"` at offset 0. The real signature is `H+` / `HX` at **offset 1024**.
- **`--find-hex`** was building an O(n) hex string of the whole file. Now streams raw bytes.
- **`readfile()`** loaded the whole input into memory with no cap — DoS risk on huge files. Now capped by `--max-size`.
- **Hexdump padding past EOF** printed stale bytes. Now emits spaces.
- **`--scan`** swallowed every error silently. Now reports what broke and continues.
- **Base64 decoder** triggered UBSan signed-int overflow on inputs whose accumulator built up past 2^25. Accumulator promoted to `uint32_t`.

## [2.0.1] — 2026-11-02

Initial public v2 release. Golfed single-file CLI with ~22 format signatures.
