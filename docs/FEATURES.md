# Feature catalog

## Detection

1. Extension-independent magic-number detection across 70+ formats
2. ISOBMFF brand dispatcher (MP4 / M4A / M4V / MOV / HEIF / HEIC / AVIF / 3GP / CR3)
3. Executable architecture hints (ELF, Mach-O LE/BE, PE/MZ, WebAssembly, Dalvik DEX)
4. Compression & container signatures (ZIP, GZIP, BZIP2, XZ, 7-Zip, RAR, LZ4, Zstandard, CAB, RPM, DEB, ar, tar)
5. Media signatures (PNG, JPEG, GIF, BMP, TIFF, WebP, PSD, OpenEXR, ICO, CUR, JPEG XL, FLAC, Ogg, MIDI, AIFF, AU, MP3 tagged + untagged, WAV, AVI, FLV, Matroska/WebM)
6. Font signatures (TTF, OTF, WOFF, WOFF2)
7. Document signatures (PDF, PostScript, RTF, XML, CFBF/OLE, CHM)
8. Database signatures (SQLite 3)
9. Filesystem signatures (NTFS, exFAT, FAT32, ext2/3/4, APFS, HFS+/HFSX, SquashFS, XFS, F2FS, btrfs, ISO 9660, QCOW2, VMDK, VHD)
10. Firmware signatures (Android boot image, Android sparse, Flattened Device Tree, SquashFS)
11. Network / forensic (libpcap LE + BE, PCAPNG, Chrome CRX)
12. Crypto / keys (PEM, OpenSSH private keys, PGP armor, OpenSSL `Salted__`)
13. Scientific data (HDF5, NumPy `.npy`, Apache Parquet, Apache Arrow IPC, Python pickle v2-5)
14. Game / asset (iNES, Doom WAD, Quake PAK, Blizzard MPQ)
15. Text-vs-binary heuristic (printable ratio > 0.97 → plain text fallback)

## Evidence

16. Confidence scoring per detection (0 – 100)
17. Per-detection evidence list with weights
18. Raw magic preview (first 32 bytes hex)
19. Streaming SHA-256 (always covers the full file)
20. Streaming CRC-32 (IEEE 802.3 / zlib / PNG polynomial)
21. Shannon entropy over the loaded window
22. Printable-byte ratio
23. Dominant-byte statistics
24. MBR / GPT partition-table evidence
25. Human-readable reports
26. JSON reports with a stable schema (see [JSON schema](json-schema.md))

## Investigation

27. ASCII string extraction
28. UTF-16LE string extraction (both 16-bit alignments)
29. Canonical hexdump with correct EOF padding
30. ASCII substring search (every match offset reported)
31. Hex-pattern byte search (every match offset reported)
32. Recursive directory inventory (`--scan DIR`)
33. Unknown-format research mode (`--deep`)
34. OS-focused unknown-format hints (`--unknown=windows|macos|linux`)
35. MIME classification
36. Base64 encode / decode

## Carving (write-side, opt-in)

37. Signature-based carving into `<offset>.<ext>` files across 14 formats
38. Conservative length estimate (trails to the next signature or EOF)
39. Nothing is decompressed, parsed past the magic, or executed

## Timeline

40. Filesystem mtime
41. ZIP local-file-header DOS mtime
42. PE/COFF `TimeDateStamp`
43. GZIP member mtime
44. PDF `/CreationDate` from the document info dict
45. PDF `/ModDate` from the document info dict

## Safety

46. Read-only on the input (no modification, no mount)
47. `--max-size` cap on in-memory structural analysis
48. Streaming hashes so huge files never load fully into RAM
49. No shell execution, no network calls
50. No third-party dependencies (standard C++17 only)

## Portability

51. Linux build (GCC, Clang)
52. macOS build (AppleClang, Xcode project under `macos/`)
53. Windows build (MSVC)
54. 3-OS CI matrix on every PR
55. Static binaries published on the Releases page
