# Format catalog

Every signature the detector knows about, with the byte pattern, the offset it's checked at, and the confidence it reports on a clean match.

## Executables

| Format | Offset | Magic | Confidence | MIME |
|---|---|---|---|---|
| Windows PE / DOS MZ | 0 | `4D 5A` | 100 | `application/vnd.microsoft.portable-executable` |
| ELF | 0 | `7F 45 4C 46` | 100 | `application/x-elf` |
| Mach-O (32/64 LE/BE) | 0 | `FE ED FA CE` / `CE FA ED FE` / `FE ED FA CF` / `CF FA ED FE` | 100 | `application/x-mach-binary` |
| Mach-O universal / Java .class | 0 | `CA FE BA BE` (collides) | 90 each (dual report) | `application/x-mach-binary` / `application/java-vm` |
| WebAssembly | 0 | `00 61 73 6D` | 100 | `application/wasm` |
| Dalvik DEX | 0 | `64 65 78 0A` | 100 | `application/x-dex` |

## Documents

| Format | Offset | Magic | Confidence | MIME |
|---|---|---|---|---|
| PDF | 0 | `25 50 44 46 2D` | 100 | `application/pdf` |
| PostScript | 0 | `25 21 50 53` | 100 | `application/postscript` |
| RTF | 0 | `7B 5C 72 74 66` | 100 | `application/rtf` |
| XML | 0 | `3C 3F 78 6D 6C` | 90 | `application/xml` |
| CFBF (OLE) | 0 | `D0 CF 11 E0 A1 B1 1A E1` | 95 | `application/x-cfb` |
| CHM | 0 | `49 54 53 46` | 100 | `application/vnd.ms-htmlhelp` |

## Images

| Format | Offset | Magic | Confidence | MIME |
|---|---|---|---|---|
| PNG | 0 | `89 50 4E 47 0D 0A 1A 0A` | 100 | `image/png` |
| JPEG | 0 | `FF D8 FF` | 100 | `image/jpeg` |
| GIF | 0 | `47 49 46 38 37 61` / `47 49 46 38 39 61` | 100 | `image/gif` |
| BMP | 0 | `42 4D` + 14-byte header | 95 | `image/bmp` |
| TIFF | 0 | `49 49 2A 00` / `4D 4D 00 2A` | 100 | `image/tiff` |
| WebP | 0 | `RIFF....WEBP` | 100 | `image/webp` |
| PSD | 0 | `38 42 50 53` | 100 | `image/vnd.adobe.photoshop` |
| OpenEXR | 0 | `76 2F 31 01` | 100 | `image/x-exr` |
| ICO | 0 | `00 00 01 00` | 90 | `image/vnd.microsoft.icon` |
| CUR | 0 | `00 00 02 00` | 90 | `image/vnd.microsoft.icon` |
| JPEG XL | 0 | `FF 0A` (codestream) or `00 00 00 0C 4A 58 4C 20` (container) | 100 | `image/jxl` |

## ISOBMFF family (dispatched on `ftyp` brand at offset 4..12)

| Brand(s) | Format | MIME |
|---|---|---|
| `isom` `iso2` `mp41` `mp42` | MP4 | `video/mp4` |
| `M4A ` | iTunes M4A audio | `audio/mp4` |
| `M4V ` | iTunes M4V video | `video/mp4` |
| `M4B ` | iTunes audiobook | `audio/mp4` |
| `qt  ` | QuickTime | `video/quicktime` |
| `heic` `heix` `heim` | HEIF/HEIC image | `image/heic` |
| `mif1` `msf1` | HEIF image sequence | `image/heif` |
| `avif` `avis` | AVIF | `image/avif` |
| `3gp4` `3gp5` | 3GP | `video/3gpp` |
| `3g2a` | 3GPP2 | `video/3gpp2` |
| `crx ` | Canon CR3 raw | `image/x-canon-cr3` |

## Fonts

| Format | Offset | Magic | Confidence | MIME |
|---|---|---|---|---|
| TrueType | 0 | `00 01 00 00` | 90 | `font/ttf` |
| OpenType CFF | 0 | `4F 54 54 4F` | 100 | `font/otf` |
| WOFF | 0 | `77 4F 46 46` | 100 | `font/woff` |
| WOFF2 | 0 | `77 4F 46 32` | 100 | `font/woff2` |

## Audio / video

| Format | Offset | Magic | Confidence | MIME |
|---|---|---|---|---|
| MP3 (ID3-tagged) | 0 | `49 44 33` | 95 | `audio/mpeg` |
| MP3 frame | 0 | `FF FB` / `FF F3` / `FF F2` | 85 | `audio/mpeg` |
| WAV | 0 + 8 | `RIFF....WAVE` | 100 | `audio/wav` |
| FLAC | 0 | `66 4C 61 43` | 100 | `audio/flac` |
| Ogg | 0 | `4F 67 67 53` | 100 | `application/ogg` |
| MIDI | 0 | `4D 54 68 64` | 100 | `audio/midi` |
| AIFF | 0 + 8 | `FORM....AIFF` | 100 | `audio/aiff` |
| Sun AU | 0 | `2E 73 6E 64` | 100 | `audio/basic` |
| AVI | 0 + 8 | `RIFF....AVI ` | 100 | `video/x-msvideo` |
| Matroska / WebM | 0 | `1A 45 DF A3` | 95 | `video/x-matroska` |
| Flash FLV | 0 | `46 4C 56 01` | 100 | `video/x-flv` |

## Compression / containers

| Format | Offset | Magic | Confidence | MIME |
|---|---|---|---|---|
| ZIP | 0 | `50 4B 03 04` / `05 06` / `07 08` | 100 | `application/zip` |
| GZIP | 0 | `1F 8B` | 100 | `application/gzip` |
| BZIP2 | 0 | `42 5A 68` | 100 | `application/x-bzip2` |
| XZ | 0 | `FD 37 7A 58 5A 00` | 100 | `application/x-xz` |
| 7-Zip | 0 | `37 7A BC AF 27 1C` | 100 | `application/x-7z-compressed` |
| RAR | 0 | `52 61 72 21 1A 07` | 100 | `application/vnd.rar` |
| TAR (ustar) | 257 | `75 73 74 61 72` | 100 | `application/x-tar` |
| LZ4 frame | 0 | `04 22 4D 18` | 100 | `application/x-lz4` |
| Zstandard | 0 | `28 B5 2F FD` | 100 | `application/zstd` |
| CAB | 0 | `4D 53 43 46` | 100 | `application/vnd.ms-cab-compressed` |
| RPM | 0 | `ED AB EE DB` | 100 | `application/x-rpm` |
| Debian .deb | 0 + 8 | `!<arch>\n` + `debian-binary` | 100 | `application/vnd.debian.binary-package` |
| Unix ar | 0 | `21 3C 61 72 63 68 3E 0A` | 100 | `application/x-archive` |
| Chrome CRX | 0 | `43 72 32 34` | 100 | `application/x-chrome-extension` |

## Filesystems / disk images

| Format | Offset | Magic | Confidence |
|---|---|---|---|
| ISO 9660 | 0x8001 | `CD001` | 100 |
| MBR (boot sector) | 510 | `55 AA` | 70 |
| GPT (EFI protective) | 512 | `EFI PART` | 100 |
| NTFS | 3 | `NTFS    ` | 100 |
| exFAT | 3 | `EXFAT   ` | 100 |
| FAT32 | 54 | `FAT32   ` | 100 |
| ext2/3/4 | 0x438 | `53 EF` | 100 |
| APFS | 0x40 | `NXSB` | 100 |
| HFS+/HFSX | 1024 | `H+` / `HX` | 100 |
| SquashFS | 0 | `68 73 71 73` | 100 |
| XFS | 0 | `58 46 53 42` | 100 |
| F2FS | 0x400 | `F2 F5 2A 10` | 100 |
| btrfs | 0x10040 | `_BHRfS_M` | 100 |
| QCOW2 | 0 | `51 46 49 FB` | 100 |
| VMDK | 0 | `4B 44 4D 56` | 100 |
| VHD (footer-at-start) | 0 | `conectix` | 95 |

## Firmware / backup

| Format | Offset | Magic | Confidence |
|---|---|---|---|
| Android boot image | 0 | `ANDROID!` | 100 |
| Android sparse image | 0 | `3A FF 26 ED` | 100 |
| Android adb backup | 0 | `ANDROID BACKUP` | 100 |
| Flattened Device Tree | 0 | `D0 0D FE ED` | 100 |

## Game / asset

| Format | Offset | Magic | Confidence |
|---|---|---|---|
| iNES ROM (NES) | 0 | `4E 45 53 1A` | 100 |
| Doom IWAD / PWAD | 0 | `IWAD` / `PWAD` | 100 |
| Quake PAK | 0 | `PACK` + size ≥ 12 | 90 |
| Blizzard MPQ | 0 | `4D 50 51 1A` | 100 |

## Network / forensic

| Format | Offset | Magic | Confidence | MIME |
|---|---|---|---|---|
| libpcap | 0 | `D4 C3 B2 A1` / `A1 B2 C3 D4` | 100 | `application/vnd.tcpdump.pcap` |
| PCAPNG | 0 | `0A 0D 0D 0A` | 100 | `application/vnd.tcpdump.pcap` |

## Crypto / keys

| Format | Offset | Magic | Confidence |
|---|---|---|---|
| OpenSSH private key | 0 | `-----BEGIN OPENSSH PRIVATE KEY-----` | 100 |
| PGP armored | 0 | `-----BEGIN PGP` | 100 |
| Generic PEM | 0 | `-----BEGIN ` (other) | 95 |
| OpenSSL `enc` | 0 | `Salted__` | 100 |

## Scientific data

| Format | Offset | Magic | Confidence |
|---|---|---|---|
| HDF5 | 0 | `89 48 44 46 0D 0A 1A 0A` | 100 |
| NumPy .npy | 0 | `93 4E 55 4D 50 59` | 100 |
| Apache Parquet | 0 | `50 41 52 31` | 95 |
| Apache Arrow IPC | 0 | `41 52 52 4F 57 31` | 100 |
| Python pickle v2-5 | 0 | `80` + `02..05` | 80 |

## Script

| Format | Offset | Magic | Confidence |
|---|---|---|---|
| Shebang | 0 | `23 21` (`#!`) | 95 |
