# Digital Archaeologist

[![Download Digital-Archaeologist](https://img.shields.io/sourceforge/dt/digi-archaeologist.svg?label=SourceForge%20downloads)](https://sourceforge.net/projects/digi-archaeologist/files/latest/download) [![Download Digital-Archaeologist](https://a.fsdn.com/con/app/sf-download-button)](https://sourceforge.net/projects/digi-archaeologist/files/latest/download)

[![CI](https://github.com/A-Hackers-Guide/digital-archaeologist/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Hackers-Guide/digital-archaeologist/actions/workflows/ci.yml)
[![Sanitize](https://github.com/A-Hackers-Guide/digital-archaeologist/actions/workflows/sanitize.yml/badge.svg)](https://github.com/A-Hackers-Guide/digital-archaeologist/actions/workflows/sanitize.yml)
[![Docs](https://github.com/A-Hackers-Guide/digital-archaeologist/actions/workflows/docs.yml/badge.svg)](https://a-hackers-guide.github.io/digital-archaeologist/)

Digital Archaeologist is an extension-independent binary archaeology toolkit for files, disk images, archives, firmware blobs, databases, executables, and unknown data. **Read-only**: it identifies what something is and what else is embedded in it, without ever writing to the input.

> 📘 Full docs: <https://a-hackers-guide.github.io/digital-archaeologist/>

## What it does

- **Identifies 70+ formats** by magic number, independent of extension.
- **Scores every detection** with weighted evidence, not a flat yes/no.
- **Streams SHA-256** over the whole file, even when a size cap limits structural analysis.
- **Carves embedded streams** out of unknown blobs by signature.
- **Extracts a timeline** from filesystem mtime plus format-embedded timestamps.
- **Dumps strings** in both ASCII and UTF-16LE in one pass.
- **Searches** for ASCII substrings and raw byte patterns with every match offset reported.
- **Emits stable JSON** with a documented schema for automation.
- **Builds natively** on Linux, macOS, and Windows from the same CMake tree.
- **Leaves the input alone.** No mounts, no drivers, no writes, ever.

## Quick start

```text
archaeologist suspicious.bin
archaeologist --json suspicious.bin
archaeologist --hash --crc32 --entropy --strings suspicious.bin
archaeologist --partitions disk.img
archaeologist --timeline report.pdf
archaeologist --carve ./out firmware.img
archaeologist --scan ./evidence
```

See the [CLI reference](https://a-hackers-guide.github.io/digital-archaeologist/CLI/) for every flag.

## The promises

Each of these is a claim about what the tool actually does **today**, backed by code and tests.

### Detection

1. **Extension-independent magic detection** for 70+ formats across executables, documents, images, fonts, audio, video, archives, filesystems, firmware, game ROMs, crypto keys, scientific data, network captures, and scripts.
2. **ISOBMFF brand dispatcher.** One `ftyp` check resolves MP4, M4A, M4V, M4B, MOV, HEIF/HEIC, AVIF, 3GP, 3GPP2, and Canon CR3.
3. **Evidence-scored confidence.** Weak magics (e.g. TTF's `00 01 00 00`) report a lower confidence with named evidence entries; strong magics (`%PDF-`, `\x89PNG`) report 100 with a single-signature evidence record.
4. **Multi-detection support.** A file is allowed to match more than one signature (e.g. ZIP + CRX, Mach-O FAT + Java class) and each is reported separately.
5. **Full format catalog documented** at <https://a-hackers-guide.github.io/digital-archaeologist/formats/> — every signature, its offset, its confidence, and its MIME.

### Fingerprinting

6. **Streaming SHA-256** across the entire file. Files larger than RAM hash correctly; verified against the NIST empty-string, `"abc"`, 1-MiB-zeros, and 1 000 000-`'a'` vectors.
7. **Streaming CRC-32** (IEEE 802.3 / zlib / PNG polynomial). Verified against the standard test vectors; streaming == batched.
8. **Shannon entropy** over the loaded window, bucketed into low/mixed/high/very-high classes.
9. **Printable-byte ratio** with a tab-aware threshold for the text fallback.
10. **Dominant-byte statistics.**

### Investigation

11. **ASCII + UTF-16LE strings** in one pass. UTF-16LE is scanned at both 16-bit alignments; output rows carry `<encoding>@<offset>: <text>`.
12. **Canonical hexdump** with correct padding past EOF.
13. **Substring search** reports **every** match offset (decimal + hex), not just the first.
14. **Byte-pattern search** via `--find-hex HEX`, streaming across the loaded window.
15. **Recursive directory inventory** (`--scan DIR`) emits `path<TAB>format<TAB>size<TAB>sha256` for every regular file.
16. **MIME-style classification** with best-guess MIME per format.
17. **MBR / GPT partition evidence.**

### Carving (opt-in, write-side)

18. **Signature-based carving** for 14 formats (ZIP, GZIP, PNG, JPEG, PDF, ELF, MZ/PE, 7z, RAR, BZIP2, XZ, Ogg, Matroska, SQLite).
19. **Conservative length estimate** (trails to the next signature or EOF). Nothing is decompressed, parsed past the magic, or executed.
20. **Deterministic output naming**: `<hex-offset>.<ext>` per carved piece.

### Timeline

21. **Filesystem mtime** on every analysed file.
22. **ZIP local-file-header DOS mtime.**
23. **PE/COFF `TimeDateStamp`** by following the `e_lfanew` → PE header offset.
24. **GZIP member mtime.**
25. **PDF `/CreationDate`** from the document info dict.
26. **PDF `/ModDate`** from the document info dict.

### Output

27. **Human-readable reports** with per-detection evidence lines.
28. **Stable JSON schema**, documented at <https://a-hackers-guide.github.io/digital-archaeologist/json-schema/>.
29. **Base64 encode / decode** via `--base64-encode` / `--base64-decode`.
30. **Report files** via `--report FILE` alongside stdout.

### Safety

31. **Read-only on the input.** No code path writes to the file passed in.
32. **`--max-size` cap** on in-memory structural analysis (default 2 GiB); SHA-256 still streams the whole file.
33. **No shell execution.** No `system()`, no `popen()`, no process spawning.
34. **No network calls.** No sockets, no `curl`, no `fetch`.
35. **No third-party runtime dependencies.** Standard C++17 only.

### Portability

36. **Linux native build** (GCC, Clang).
37. **macOS native build** (AppleClang + Xcode CLT; separate Xcode project under `macos/`).
38. **Windows native build** (MSVC).
39. **3-OS CI matrix** on every PR.
40. **Static release binaries** published per OS on the [Releases page](https://github.com/A-Hackers-Guide/digital-archaeologist/releases).

### Correctness

41. **70+ fixture-asserted detections** in `tests/detect_test.cpp`.
42. **SHA-256 NIST vectors** in `tests/sha256_test.cpp`.
43. **CRC-32 test vectors + streaming equivalence** in `tests/crc32_test.cpp`.
44. **Base64 RFC 4648 round-trip** in `tests/base64_test.cpp`.
45. **String-extraction tests** covering ASCII + UTF-16LE.
46. **Carver round-trip tests** covering ZIP + GZIP + PNG + JPEG concatenations.
47. **Timeline tests** covering GZIP mtime + ZIP DOS time recovery.
48. **ASan + UBSan CI job** on every PR (Ubuntu + clang).
49. **libFuzzer targets** on `da::analyze_bytes` and `da::carve`, run under ASan + UBSan for 60 seconds each on every PR.
50. **CodeRabbit review** attached to every PR.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Requires CMake ≥ 3.20 and a C++17 compiler. **Zero third-party runtime deps.**

### Opt-in fuzz build

```bash
cmake -S . -B build-fuzz \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DDA_FUZZ=ON \
  -DCMAKE_CXX_FLAGS="-O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-fuzz --parallel
./build-fuzz/fuzz/da_fuzz_analyze -max_total_time=60 corpus/
```

## Safety model

Digital Archaeologist **reads** evidence and **produces** reports. Everything under `drivers/` is documentation-only unless explicitly implemented and reviewed. No kernel driver is silently installed. Encryption support is metadata / recovery-path analysis, never unrestricted password cracking or security bypass.

## Documentation

- **Full site:** <https://a-hackers-guide.github.io/digital-archaeologist/>
- `docs/index.md` — landing page
- `docs/CLI.md` — command reference
- `docs/FEATURES.md` — 55-item numbered capability list
- `docs/formats.md` — per-format magic / offset / confidence / MIME
- `docs/json-schema.md` — `--json` schema
- `docs/ARCHITECTURE.md` — internals
- `docs/FORENSICS.md` — evidence workflow
- `docs/UNKNOWN_FORMATS.md` — unknown-format research
- `docs/MACOS.md` — Xcode / CLT build notes
- `docs/INSTALL.md` — installation
- `CHANGELOG.md` — release notes

## License

MIT. See [`LICENSE`](LICENSE) and [`LICENSE-MIT`](LICENSE-MIT).
