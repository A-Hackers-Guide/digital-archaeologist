# Digital Archaeologist

**Universal binary, disk-image, container, and filesystem archaeology — v1 prototype.**

Digital Archaeologist deliberately ignores filename extensions and starts from raw bytes and structural evidence. The first public pre-release is `v1.0.0-pre1`.

## v1 prototype
- Extension-independent magic/signature detection.
- Windows PE/DOS, ELF, Mach-O/universal, PDF, PNG, JPEG, GIF.
- ZIP, GZIP, 7-Zip, RAR and SQLite detection.
- MBR-compatible boot-sector and GPT-header detection.
- NTFS, exFAT, FAT12/16/32, ext2/3/4, APFS, HFS+ heuristic, ISO 9660, SquashFS.
- SHA-256 hashing implemented without third-party runtime dependencies.
- Shannon entropy measurement for compression/encryption/packing clues.
- Evidence-backed confidence scores.
- Read-only unknown-format profile.
- Exact-byte Base64 transport encode/decode.
- Windows/macOS/Linux-oriented CLI profiles.
- CTest smoke tests and CMake build.

## Build

```text
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

On Windows the executable is normally `build\Release\archaeologist.exe`.

## Examples

```text
archaeologist mystery.bin
archaeologist --unknown mystery.bin
archaeologist --linux image.bin
archaeologist --macos image.bin
archaeologist --windows image.bin
archaeologist --password encrypted.bin
archaeologist --transport-encode mystery.bin > payload.txt
archaeologist --transport-decode payload.txt
```

## What v1 does NOT claim

A signature match is not the same as complete filesystem reconstruction. Unknown proprietary formats are reported as unresolved rather than invented. Encryption is identified/analyzed but not defeated. The prototype does not install or execute kernel drivers and does not modify disks.

## Roadmap

v1.x: recursive containers, partition-table decoding, filesystem superblock parsing, strings/hex views, structural hypotheses, richer evidence graphs, known-specimen comparison, and long-running research sessions.

v2: sandboxed read-only filesystem adapters/drivers only after extensive user-space validation.

## License

MIT. See `LICENSE`.
