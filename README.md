# Digital Archaeologist v2

Digital Archaeologist is an extension-independent binary archaeology toolkit for files, disk images, archives, firmware blobs, databases, executables, and unknown data.

## Highlights

- 20+ analysis capabilities in one CLI
- Magic/signature detection independent of file extensions
- SHA-256 integrity fingerprints
- Entropy and printable-byte analysis
- Strings extraction
- Hex inspection
- MBR/GPT evidence inspection
- ZIP/GZIP/BZIP2/XZ/7z/RAR detection
- PE/ELF/Mach-O-adjacent executable identification
- PDF/image/audio/database identification
- MIME-style classification
- JSON output for automation
- Human-readable forensic reports
- Recursive directory inventory
- ASCII and hexadecimal searching
- Base64 transport mode
- Unknown-format research mode
- OS-focused unknown modes
- Evidence/confidence reporting
- Read-only design
- Windows native build
- macOS/Xcode + Command Line Tools build path
- Linux native build

> v2.0 is a major functionality release. It is intentionally read-only: it does not mount, modify, or repair user media.

## Quick start

```text
archaeologist suspicious.bin
archaeologist --json suspicious.bin
archaeologist --hash --entropy --strings suspicious.bin
archaeologist --partitions disk.img
archaeologist --scan ./evidence
archaeologist --unknown=macos mystery.img
archaeologist --help unknown
```

## Build

```text
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Windows, macOS, and Linux are first-class targets. macOS also has an Xcode project under `macos/`; it checks for the active Xcode Command Line Tools developer directory before building.

## Safety model

Digital Archaeologist reads evidence and produces reports. Experimental filesystem-driver directories are documentation-only unless explicitly implemented and reviewed. No kernel driver is silently installed. Encryption support is metadata/recovery-path analysis rather than unrestricted password cracking or security bypass.

## Documentation

- `docs/FEATURES.md` — feature catalog
- `docs/CLI.md` — command reference
- `docs/ARCHITECTURE.md` — internals
- `docs/FORENSICS.md` — evidence workflow
- `docs/UNKNOWN_FORMATS.md` — unknown-format research
- `docs/MACOS.md` — Xcode/CLT build
- `docs/INSTALL.md` — installation
- `drivers/README.md` — experimental read-only driver plan

## License

MIT. See `LICENSE` and `LICENSE-MIT`.
