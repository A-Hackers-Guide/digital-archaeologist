#include "analyzer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "hashing.hpp"

namespace da {
namespace {

using Bytes = std::vector<unsigned char>;

inline bool starts_with(const Bytes& d, std::initializer_list<unsigned char> s,
                        std::size_t off = 0) {
  if (off + s.size() > d.size()) return false;
  return std::equal(s.begin(), s.end(), d.begin() + off);
}

inline bool starts_with_str(const Bytes& d, const char* s, std::size_t off = 0) {
  std::size_t n = std::strlen(s);
  if (off + n > d.size()) return false;
  return std::memcmp(d.data() + off, s, n) == 0;
}

void add(std::vector<Detection>& out, std::string category, std::string format,
         int confidence, std::string mime,
         std::initializer_list<Evidence> evidence) {
  Detection d;
  d.category = std::move(category);
  d.format = std::move(format);
  d.confidence = confidence;
  d.mime = std::move(mime);
  d.evidence.assign(evidence.begin(), evidence.end());
  out.push_back(std::move(d));
}

void detect_signatures(const Bytes& d, std::vector<Detection>& out) {
  // --- Executables ---
  if (starts_with(d, {0x4d, 0x5a})) {
    add(out, "executable", "Windows PE / DOS MZ", 100,
        "application/vnd.microsoft.portable-executable",
        {{"signature", "MZ header at offset 0", 100}});
  }
  if (starts_with(d, {0x7f, 'E', 'L', 'F'})) {
    add(out, "executable", "ELF", 100, "application/x-elf",
        {{"signature", "\\x7FELF at offset 0", 100}});
  }
  if (starts_with(d, {0xfe, 0xed, 0xfa, 0xce}) ||
      starts_with(d, {0xce, 0xfa, 0xed, 0xfe}) ||
      starts_with(d, {0xfe, 0xed, 0xfa, 0xcf}) ||
      starts_with(d, {0xcf, 0xfa, 0xed, 0xfe})) {
    add(out, "executable", "Mach-O", 100, "application/x-mach-binary",
        {{"signature", "Mach-O magic", 100}});
  }
  if (starts_with(d, {0xca, 0xfe, 0xba, 0xbe}) ||
      starts_with(d, {0xbe, 0xba, 0xfe, 0xca})) {
    // 0xCAFEBABE collides with Java .class files (same magic). Flag both.
    add(out, "executable", "Mach-O universal (fat binary)", 90,
        "application/x-mach-binary",
        {{"signature", "0xCAFEBABE", 60},
         {"ambiguity", "collides with Java .class", 30}});
    add(out, "executable", "Java class file", 90, "application/java-vm",
        {{"signature", "0xCAFEBABE", 60},
         {"ambiguity", "collides with Mach-O FAT", 30}});
  }

  // --- Documents / markup ---
  if (starts_with(d, {0x25, 0x50, 0x44, 0x46, 0x2d})) {
    add(out, "document", "PDF", 100, "application/pdf",
        {{"signature", "%PDF- header", 100}});
  }

  // --- Images ---
  if (starts_with(d, {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})) {
    add(out, "image", "PNG", 100, "image/png",
        {{"signature", "PNG magic", 100}});
  }
  if (starts_with(d, {0xff, 0xd8, 0xff})) {
    add(out, "image", "JPEG", 100, "image/jpeg",
        {{"signature", "JPEG SOI", 100}});
  }
  if (starts_with(d, {'G', 'I', 'F', '8', '7', 'a'}) ||
      starts_with(d, {'G', 'I', 'F', '8', '9', 'a'})) {
    add(out, "image", "GIF", 100, "image/gif",
        {{"signature", "GIF87a / GIF89a", 100}});
  }
  if (starts_with(d, {'B', 'M'}) && d.size() >= 14) {
    // BMP file header is 14 bytes; size field at offset 2 is a weak check.
    add(out, "image", "BMP", 95, "image/bmp",
        {{"signature", "BM header", 80},
         {"structure", "14-byte file header present", 15}});
  }

  // --- Archives / compression ---
  if (starts_with(d, {'P', 'K', 0x03, 0x04}) ||
      starts_with(d, {'P', 'K', 0x05, 0x06}) ||
      starts_with(d, {'P', 'K', 0x07, 0x08})) {
    add(out, "container", "ZIP", 100, "application/zip",
        {{"signature", "PK ZIP signature", 100}});
  }
  if (starts_with(d, {0x1f, 0x8b})) {
    add(out, "container", "GZIP", 100, "application/gzip",
        {{"signature", "gzip magic 1F 8B", 100}});
  }
  if (starts_with(d, {'B', 'Z', 'h'})) {
    add(out, "container", "BZIP2", 100, "application/x-bzip2",
        {{"signature", "BZh header", 100}});
  }
  if (starts_with(d, {0xfd, '7', 'z', 'X', 'Z', 0x00})) {
    add(out, "container", "XZ", 100, "application/x-xz",
        {{"signature", "XZ magic", 100}});
  }
  if (starts_with(d, {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c})) {
    add(out, "container", "7-Zip", 100, "application/x-7z-compressed",
        {{"signature", "7z magic", 100}});
  }
  if (starts_with(d, {'R', 'a', 'r', '!', 0x1a, 0x07})) {
    add(out, "container", "RAR", 100, "application/vnd.rar",
        {{"signature", "Rar! marker", 100}});
  }
  if (starts_with_str(d, "ustar", 257) && d.size() >= 265) {
    add(out, "container", "TAR (POSIX ustar)", 100,
        "application/x-tar",
        {{"signature", "ustar at offset 257", 100}});
  }

  // --- Audio ---
  if (starts_with(d, {'I', 'D', '3'})) {
    add(out, "audio", "MP3 (ID3v2 tagged)", 95, "audio/mpeg",
        {{"signature", "ID3 tag header", 95}});
  } else if (starts_with(d, {0xff, 0xfb}) || starts_with(d, {0xff, 0xf3}) ||
             starts_with(d, {0xff, 0xf2})) {
    add(out, "audio", "MP3 frame", 85, "audio/mpeg",
        {{"signature", "MPEG audio sync + Layer III", 85}});
  }
  if (starts_with(d, {'R', 'I', 'F', 'F'}) && d.size() >= 12 &&
      starts_with_str(d, "WAVE", 8)) {
    add(out, "audio", "WAV (RIFF/WAVE)", 100, "audio/wav",
        {{"signature", "RIFF...WAVE", 100}});
  }

  // --- Database ---
  if (d.size() >= 16 && starts_with_str(d, "SQLite format 3")) {
    add(out, "database", "SQLite 3", 100, "application/vnd.sqlite3",
        {{"signature", "SQLite format 3\\0", 100}});
  }

  // --- Filesystems / disk images ---
  if (d.size() >= 0x8006 && starts_with_str(d, "CD001", 0x8001)) {
    add(out, "filesystem", "ISO 9660", 100, "application/x-iso9660-image",
        {{"signature", "CD001 at offset 0x8001", 100}});
  }
  if (d.size() >= 512 && d[510] == 0x55 && d[511] == 0xaa) {
    add(out, "partition", "MBR-compatible boot sector", 70, "",
        {{"signature", "0x55AA at offset 510", 50},
         {"structure", "needs partition-table inspection to confirm", 20}});
  }
  if (d.size() >= 520 && starts_with_str(d, "EFI PART", 512)) {
    add(out, "partition", "GPT (EFI protective header)", 100, "",
        {{"signature", "EFI PART at LBA1", 100}});
  }
  if (d.size() >= 11 && starts_with_str(d, "NTFS    ", 3)) {
    add(out, "filesystem", "NTFS", 100, "",
        {{"signature", "NTFS OEM id", 100}});
  }
  if (d.size() >= 11 && starts_with_str(d, "EXFAT   ", 3)) {
    add(out, "filesystem", "exFAT", 100, "",
        {{"signature", "EXFAT OEM id", 100}});
  }
  if (d.size() >= 90 && starts_with_str(d, "FAT32   ", 54)) {
    add(out, "filesystem", "FAT32", 100, "",
        {{"signature", "FAT32 label", 100}});
  }
  if (d.size() >= 0x43a && d[0x438] == 0x53 && d[0x439] == 0xef) {
    add(out, "filesystem", "ext2/ext3/ext4", 100, "",
        {{"signature", "superblock magic 0xEF53 at 0x438", 100}});
  }
  if (d.size() >= 0x48 &&
      std::memcmp(d.data() + 0x40, "NXSB", 4) == 0) {
    add(out, "filesystem", "APFS", 100, "",
        {{"signature", "NXSB container superblock", 100}});
  }
  // HFS+: signature "H+" (0x482B) at offset 1024, or HFSX (0x4858).
  if (d.size() >= 1026 && d[1024] == 'H' && (d[1025] == '+' || d[1025] == 'X')) {
    add(out, "filesystem", "HFS+/HFSX", 100, "",
        {{"signature",
          d[1025] == '+' ? "H+ at offset 1024" : "HX at offset 1024", 100}});
  }
  if (starts_with(d, {'h', 's', 'q', 's'})) {
    add(out, "filesystem", "SquashFS", 100, "application/vnd.squashfs",
        {{"signature", "hsqs superblock", 100}});
  }
  if (starts_with(d, {'X', 'F', 'S', 'B'})) {
    add(out, "filesystem", "XFS", 100, "",
        {{"signature", "XFSB superblock", 100}});
  }
  if (d.size() >= 0x404 &&
      starts_with(d, {0xf2, 0xf5, 0x2a, 0x10}, 0x400)) {
    add(out, "filesystem", "F2FS", 100, "",
        {{"signature", "F2FS magic at offset 0x400", 100}});
  }
  if (d.size() >= 0x10048 &&
      starts_with_str(d, "_BHRfS_M", 0x10040)) {
    add(out, "filesystem", "btrfs", 100, "",
        {{"signature", "_BHRfS_M superblock at 0x10040", 100}});
  }
  if (starts_with(d, {'Q', 'F', 'I', 0xfb})) {
    add(out, "disk-image", "QCOW2", 100, "",
        {{"signature", "QFI\\xFB header", 100}});
  }
  if (starts_with(d, {'K', 'D', 'M', 'V'})) {
    add(out, "disk-image", "VMDK", 100,
        "application/vnd.vmware.vmdk-stream",
        {{"signature", "KDMV header", 100}});
  }
  if (starts_with_str(d, "conectix")) {
    add(out, "disk-image", "VHD (footer-at-start variant / copy)", 95, "",
        {{"signature", "conectix cookie", 95}});
  }

  // --- Additional images ---
  if (starts_with(d, {'I', 'I', 0x2a, 0x00}) ||
      starts_with(d, {'M', 'M', 0x00, 0x2a})) {
    add(out, "image", "TIFF", 100, "image/tiff",
        {{"signature", "TIFF byte-order + 42", 100}});
  }
  if (starts_with(d, {'R', 'I', 'F', 'F'}) && d.size() >= 12 &&
      starts_with_str(d, "WEBP", 8)) {
    add(out, "image", "WebP", 100, "image/webp",
        {{"signature", "RIFF...WEBP", 100}});
  }
  if (starts_with(d, {'R', 'I', 'F', 'F'}) && d.size() >= 12 &&
      starts_with_str(d, "AVI ", 8)) {
    add(out, "video", "AVI", 100, "video/x-msvideo",
        {{"signature", "RIFF...AVI ", 100}});
  }
  // ISOBMFF family: MP4, MOV, HEIF/HEIC, AVIF, 3GP, M4A, CR3...
  if (d.size() >= 12 && starts_with_str(d, "ftyp", 4)) {
    std::string brand(reinterpret_cast<const char*>(d.data() + 8), 4);
    struct Brand { const char* brand; const char* format; const char* mime;
                   const char* cat; };
    static const Brand kBrands[] = {
        {"heic", "HEIF/HEIC image", "image/heic", "image"},
        {"heix", "HEIF/HEIC image", "image/heic", "image"},
        {"heim", "HEIF/HEIC image", "image/heic", "image"},
        {"mif1", "HEIF image sequence", "image/heif", "image"},
        {"msf1", "HEIF image sequence", "image/heif", "image"},
        {"avif", "AVIF image", "image/avif", "image"},
        {"avis", "AVIF image sequence", "image/avif", "image"},
        {"isom", "MP4 (ISO base media)", "video/mp4", "video"},
        {"iso2", "MP4 (ISO base media)", "video/mp4", "video"},
        {"mp41", "MP4", "video/mp4", "video"},
        {"mp42", "MP4", "video/mp4", "video"},
        {"M4A ", "iTunes M4A audio", "audio/mp4", "audio"},
        {"M4V ", "iTunes M4V video", "video/mp4", "video"},
        {"M4B ", "iTunes M4B audiobook", "audio/mp4", "audio"},
        {"qt  ", "QuickTime movie", "video/quicktime", "video"},
        {"3gp4", "3GP", "video/3gpp", "video"},
        {"3gp5", "3GP", "video/3gpp", "video"},
        {"3g2a", "3GPP2", "video/3gpp2", "video"},
        {"crx ", "Canon CR3 raw", "image/x-canon-cr3", "image"},
    };
    bool matched = false;
    for (const auto& b : kBrands) {
      if (brand == b.brand) {
        add(out, b.cat, b.format, 100, b.mime,
            {{"signature", std::string("ftyp brand '") + b.brand + "'", 100}});
        matched = true;
        break;
      }
    }
    if (!matched) {
      add(out, "container", "ISOBMFF (unknown brand " + brand + ")", 85, "",
          {{"signature", "ftyp box", 85}});
    }
  }
  if (starts_with(d, {'8', 'B', 'P', 'S'})) {
    add(out, "image", "PSD (Photoshop)", 100,
        "image/vnd.adobe.photoshop",
        {{"signature", "8BPS header", 100}});
  }
  if (starts_with(d, {0x76, 0x2f, 0x31, 0x01})) {
    add(out, "image", "OpenEXR", 100, "image/x-exr",
        {{"signature", "OpenEXR magic", 100}});
  }
  if (starts_with(d, {0x00, 0x00, 0x01, 0x00})) {
    add(out, "image", "ICO (Windows icon)", 90, "image/vnd.microsoft.icon",
        {{"signature", "ICO header", 90}});
  }
  if (starts_with(d, {0x00, 0x00, 0x02, 0x00})) {
    add(out, "image", "CUR (Windows cursor)", 90, "image/vnd.microsoft.icon",
        {{"signature", "CUR header", 90}});
  }
  if (starts_with(d, {0xff, 0x0a}) ||
      starts_with(d, {0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58, 0x4c, 0x20})) {
    add(out, "image", "JPEG XL", 100, "image/jxl",
        {{"signature", "JPEG XL codestream or container", 100}});
  }
  if (starts_with(d, {0x89, 'H', 'D', 'F', 0x0d, 0x0a, 0x1a, 0x0a})) {
    add(out, "data", "HDF5", 100, "application/x-hdf5",
        {{"signature", "HDF5 superblock", 100}});
  }

  // --- Fonts ---
  if (starts_with(d, {0x00, 0x01, 0x00, 0x00})) {
    add(out, "font", "TrueType (TTF)", 90, "font/ttf",
        {{"signature", "TTF sfnt version 1.0", 90}});
  }
  if (starts_with(d, {'O', 'T', 'T', 'O'})) {
    add(out, "font", "OpenType CFF (OTF)", 100, "font/otf",
        {{"signature", "OTTO sfnt version", 100}});
  }
  if (starts_with(d, {'w', 'O', 'F', 'F'})) {
    add(out, "font", "WOFF", 100, "font/woff",
        {{"signature", "wOFF header", 100}});
  }
  if (starts_with(d, {'w', 'O', 'F', '2'})) {
    add(out, "font", "WOFF2", 100, "font/woff2",
        {{"signature", "wOF2 header", 100}});
  }

  // --- Additional audio ---
  if (starts_with(d, {'f', 'L', 'a', 'C'})) {
    add(out, "audio", "FLAC", 100, "audio/flac",
        {{"signature", "fLaC header", 100}});
  }
  if (starts_with(d, {'O', 'g', 'g', 'S'})) {
    add(out, "audio", "Ogg (Vorbis / Opus / FLAC / Theora)", 100,
        "application/ogg",
        {{"signature", "OggS page", 100}});
  }
  if (starts_with(d, {'M', 'T', 'h', 'd'})) {
    add(out, "audio", "Standard MIDI file", 100, "audio/midi",
        {{"signature", "MThd header", 100}});
  }
  if (starts_with(d, {'F', 'O', 'R', 'M'}) && d.size() >= 12 &&
      starts_with_str(d, "AIFF", 8)) {
    add(out, "audio", "AIFF", 100, "audio/aiff",
        {{"signature", "FORM...AIFF", 100}});
  }
  if (starts_with(d, {'.', 's', 'n', 'd'})) {
    add(out, "audio", "Sun AU / NeXT .snd", 100, "audio/basic",
        {{"signature", ".snd header", 100}});
  }

  // --- Video ---
  if (starts_with(d, {0x1a, 0x45, 0xdf, 0xa3})) {
    add(out, "video", "Matroska / WebM (EBML)", 95, "video/x-matroska",
        {{"signature", "EBML header", 95}});
  }
  if (starts_with(d, {'F', 'L', 'V', 0x01})) {
    add(out, "video", "Flash FLV", 100, "video/x-flv",
        {{"signature", "FLV header", 100}});
  }

  // --- Additional compression / containers ---
  if (starts_with(d, {0x04, 0x22, 0x4d, 0x18})) {
    add(out, "container", "LZ4 frame", 100, "application/x-lz4",
        {{"signature", "LZ4 frame magic", 100}});
  }
  if (starts_with(d, {0x28, 0xb5, 0x2f, 0xfd})) {
    add(out, "container", "Zstandard", 100, "application/zstd",
        {{"signature", "zstd frame magic", 100}});
  }
  if (starts_with(d, {'M', 'S', 'C', 'F'})) {
    add(out, "container", "Microsoft CAB", 100, "application/vnd.ms-cab-compressed",
        {{"signature", "MSCF header", 100}});
  }
  if (starts_with(d, {0xed, 0xab, 0xee, 0xdb})) {
    add(out, "container", "RPM package", 100, "application/x-rpm",
        {{"signature", "RPM lead magic", 100}});
  }
  if (starts_with_str(d, "!<arch>\n")) {
    if (d.size() >= 16 && starts_with_str(d, "debian-binary", 8)) {
      add(out, "container", "Debian .deb", 100, "application/vnd.debian.binary-package",
          {{"signature", "ar archive + debian-binary", 100}});
    } else {
      add(out, "container", "Unix ar archive", 100, "application/x-archive",
          {{"signature", "!<arch>\\n", 100}});
    }
  }

  // --- Office / documents ---
  if (starts_with(d, {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})) {
    add(out, "document", "CFBF (OLE / legacy MS Office)", 95,
        "application/x-cfb",
        {{"signature", "CFBF compound document header", 95}});
  }
  if (starts_with_str(d, "%!PS")) {
    add(out, "document", "PostScript", 100, "application/postscript",
        {{"signature", "%!PS marker", 100}});
  }
  if (starts_with_str(d, "ITSF")) {
    add(out, "document", "CHM (Compiled HTML Help)", 100,
        "application/vnd.ms-htmlhelp",
        {{"signature", "ITSF header", 100}});
  }
  if (starts_with_str(d, "{\\rtf")) {
    add(out, "document", "RTF", 100, "application/rtf",
        {{"signature", "{\\rtf marker", 100}});
  }
  if (starts_with_str(d, "<?xml")) {
    add(out, "document", "XML", 90, "application/xml",
        {{"signature", "<?xml declaration", 90}});
  }

  // --- Executables / platform ---
  if (starts_with(d, {0x00, 'a', 's', 'm'})) {
    add(out, "executable", "WebAssembly (wasm)", 100,
        "application/wasm",
        {{"signature", "\\x00asm header", 100}});
  }
  if (starts_with(d, {'d', 'e', 'x', '\n'})) {
    add(out, "executable", "Dalvik DEX", 100,
        "application/x-dex",
        {{"signature", "dex\\n header", 100}});
  }
  if (starts_with_str(d, "ANDROID!")) {
    add(out, "firmware", "Android boot image", 100, "",
        {{"signature", "ANDROID! header", 100}});
  }
  if (starts_with(d, {0x3a, 0xff, 0x26, 0xed})) {
    add(out, "firmware", "Android sparse image", 100, "",
        {{"signature", "Android sparse magic", 100}});
  }
  if (starts_with_str(d, "ANDROID BACKUP")) {
    add(out, "backup", "Android backup (adb backup)", 100, "",
        {{"signature", "ANDROID BACKUP header", 100}});
  }
  if (starts_with(d, {0xd0, 0x0d, 0xfe, 0xed})) {
    add(out, "firmware", "Flattened Device Tree (DTB)", 100, "",
        {{"signature", "FDT magic", 100}});
  }

  // --- Game-related ---
  if (starts_with(d, {'N', 'E', 'S', 0x1a})) {
    add(out, "game-rom", "iNES ROM (NES)", 100, "application/x-nes-rom",
        {{"signature", "iNES header", 100}});
  }
  if (starts_with_str(d, "IWAD") || starts_with_str(d, "PWAD")) {
    add(out, "game-asset", "Doom WAD", 100, "application/x-doom-wad",
        {{"signature", "IWAD/PWAD header", 100}});
  }
  if (starts_with_str(d, "PACK") && d.size() >= 12) {
    add(out, "game-asset", "Quake PAK", 90, "",
        {{"signature", "PACK header", 90}});
  }
  if (starts_with(d, {'M', 'P', 'Q', 0x1a})) {
    add(out, "game-asset", "Blizzard MPQ", 100, "",
        {{"signature", "MPQ header", 100}});
  }

  // --- Network capture / forensic ---
  if (starts_with(d, {0xd4, 0xc3, 0xb2, 0xa1}) ||
      starts_with(d, {0xa1, 0xb2, 0xc3, 0xd4})) {
    add(out, "capture", "libpcap", 100, "application/vnd.tcpdump.pcap",
        {{"signature", "pcap magic", 100}});
  }
  if (starts_with(d, {0x0a, 0x0d, 0x0d, 0x0a})) {
    add(out, "capture", "PCAPNG", 100, "application/vnd.tcpdump.pcap",
        {{"signature", "PCAPNG section header block", 100}});
  }
  if (starts_with_str(d, "Cr24")) {
    add(out, "container", "Chrome CRX extension", 100,
        "application/x-chrome-extension",
        {{"signature", "Cr24 header", 100}});
  }

  // --- Crypto / keys / certs ---
  if (starts_with_str(d, "-----BEGIN ")) {
    if (starts_with_str(d, "-----BEGIN OPENSSH PRIVATE KEY-----")) {
      add(out, "key", "OpenSSH private key", 100,
          "application/x-pem-file",
          {{"signature", "OpenSSH PEM header", 100}});
    } else if (starts_with_str(d, "-----BEGIN PGP")) {
      add(out, "key", "PGP armored message/key", 100,
          "application/pgp",
          {{"signature", "PGP armor header", 100}});
    } else {
      add(out, "key", "PEM-encoded data (certificate/key)", 95,
          "application/x-pem-file",
          {{"signature", "-----BEGIN ...-----", 95}});
    }
  }
  if (starts_with_str(d, "Salted__")) {
    add(out, "crypto", "OpenSSL enc (salted)", 100, "",
        {{"signature", "Salted__ header (openssl enc)", 100}});
  }

  // --- Data / science formats ---
  if (starts_with(d, {0x93, 'N', 'U', 'M', 'P', 'Y'})) {
    add(out, "data", "NumPy .npy", 100, "",
        {{"signature", "\\x93NUMPY header", 100}});
  }
  if (starts_with_str(d, "PAR1")) {
    add(out, "data", "Apache Parquet", 95, "",
        {{"signature", "PAR1 header", 95}});
  }
  if (starts_with_str(d, "ARROW1")) {
    add(out, "data", "Apache Arrow IPC", 100, "",
        {{"signature", "ARROW1 header", 100}});
  }
  if (d.size() >= 2 && d[0] == 0x80 &&
      (d[1] >= 0x02 && d[1] <= 0x05)) {
    add(out, "data", "Python pickle (protocol 2-5)", 80,
        "application/x-pickle",
        {{"signature", "pickle protocol opcode", 80}});
  }

  // --- Scripts ---
  if (starts_with_str(d, "#!")) {
    add(out, "script", "Script with shebang", 95, "text/x-script",
        {{"signature", "#! interpreter line", 95}});
  }

  // ======================================================================
  //  Tier-F additions: 30 more formats
  // ======================================================================

  // Databases + DB sidecar files
  if (starts_with(d, {0x37, 0x7F, 0x06, 0x82}) ||
      starts_with(d, {0x37, 0x7F, 0x06, 0x83})) {
    add(out, "database", "SQLite WAL", 100, "",
        {{"signature", "SQLite write-ahead log magic", 100}});
  }
  if (starts_with(d, {0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7})) {
    add(out, "database", "SQLite rollback journal", 100, "",
        {{"signature", "SQLite journal magic", 100}});
  }
  if (starts_with_str(d, "REDIS")) {
    add(out, "database", "Redis RDB snapshot", 95, "",
        {{"signature", "REDIS magic", 95}});
  }

  // Bytecode / VMs
  if (starts_with(d, {0x1b, 'L', 'u', 'a'})) {
    add(out, "bytecode", "Lua compiled chunk", 100, "",
        {{"signature", "\\x1BLua header", 100}});
  }

  // Disk images
  if (starts_with_str(d, "QED")) {
    add(out, "disk-image", "QEMU QED", 100, "",
        {{"signature", "QED header", 100}});
  }
  if (starts_with_str(d, "<<< Oracle VM VirtualBox Disk Image >>>")) {
    add(out, "disk-image", "VirtualBox VDI", 100, "",
        {{"signature", "VDI preheader string", 100}});
  }

  // Game ROMs / binaries
  if (starts_with(d, {0x80, 0x37, 0x12, 0x40})) {
    add(out, "game-rom", "Nintendo 64 ROM (.z64, big-endian)", 100, "",
        {{"signature", "N64 header 80 37 12 40", 100}});
  }
  if (starts_with_str(d, "PFS0")) {
    add(out, "game-rom", "Nintendo Switch NSP / NCA (PFS0)", 100, "",
        {{"signature", "PFS0 header", 100}});
  }
  if (d.size() >= 0x104 && starts_with_str(d, "HEAD", 0x100)) {
    add(out, "game-rom", "Nintendo Switch XCI (gamecard)", 95, "",
        {{"signature", "HEAD at offset 0x100", 95}});
  }
  if (starts_with_str(d, "XBEH")) {
    add(out, "game-rom", "Xbox XBE executable", 100, "",
        {{"signature", "XBEH header", 100}});
  }
  if (starts_with_str(d, "XEX2")) {
    add(out, "game-rom", "Xbox 360 XEX2 executable", 100, "",
        {{"signature", "XEX2 header", 100}});
  }
  if (starts_with_str(d, "PS-X EXE")) {
    add(out, "game-rom", "PlayStation 1 PS-X EXE", 100, "",
        {{"signature", "PS-X EXE header", 100}});
  }

  // Bethesda / modding
  if (starts_with_str(d, "TES3") || starts_with_str(d, "TES4") ||
      starts_with_str(d, "TES5")) {
    add(out, "game-asset", "Bethesda ESM/ESP plugin", 100, "",
        {{"signature", "TES3/TES4/TES5 header", 100}});
  }
  if (starts_with_str(d, "BSA\0", 0)) {
    add(out, "game-asset", "Bethesda BSA archive", 100, "",
        {{"signature", "BSA header", 100}});
  }

  // Audio (extra)
  if (starts_with(d, {'R', 'I', 'F', 'F'}) && d.size() >= 12 &&
      starts_with_str(d, "sfbk", 8)) {
    add(out, "audio", "SoundFont 2 (RIFF/sfbk)", 100,
        "audio/x-soundfont",
        {{"signature", "RIFF...sfbk", 100}});
  }
  if (starts_with(d, {0x7f, 0xfe, 0x80, 0x01})) {
    add(out, "audio", "DTS Coherent Acoustics", 100, "audio/vnd.dts",
        {{"signature", "DTS sync word", 100}});
  }
  if (starts_with(d, {0x0b, 0x77})) {
    add(out, "audio", "AC-3 (Dolby Digital)", 85, "audio/ac3",
        {{"signature", "AC-3 sync word", 85}});
  }

  // 3D / scientific
  if (starts_with_str(d, "glTF")) {
    add(out, "3d-model", "glTF binary (.glb)", 100, "model/gltf-binary",
        {{"signature", "glTF header", 100}});
  }
  if (starts_with(d, {'O', 'b', 'j', 0x01})) {
    add(out, "data", "Apache Avro container", 100,
        "application/vnd.apache.avro+binary",
        {{"signature", "Obj\\x01 header", 100}});
  }

  // Windows forensic / event logs
  if (starts_with_str(d, "ElfFile\0")) {
    add(out, "log", "Windows Event Log (EVTX)", 100,
        "application/x-ms-evtx",
        {{"signature", "ElfFile header", 100}});
  }
  if (starts_with_str(d, "PAGEDUMP") || starts_with_str(d, "PAGEDU64")) {
    add(out, "memory-dump", "Windows crash dump", 100, "",
        {{"signature", "PAGEDUMP / PAGEDU64 header", 100}});
  }

  // Compression + archives (extra)
  if (starts_with(d, {'b', 'v', 'x', '-'}) ||
      starts_with(d, {'b', 'v', 'x', '1'}) ||
      starts_with(d, {'b', 'v', 'x', '2'}) ||
      starts_with(d, {'b', 'v', 'x', 'n'})) {
    add(out, "container", "Apple LZFSE", 100, "application/x-lzfse",
        {{"signature", "bvx* block header", 100}});
  }
  if (starts_with_str(d, "xar!")) {
    add(out, "container", "xar archive", 100, "application/x-xar",
        {{"signature", "xar! magic", 100}});
  }
  if (starts_with(d, {0x60, 0xea})) {
    add(out, "container", "ARJ archive", 85, "application/x-arj",
        {{"signature", "ARJ sync bytes", 85}});
  }
  if (d.size() >= 7 && starts_with_str(d, "-lh", 2)) {
    // LHA/LZH typically: "..-lh0-" at offset 2
    add(out, "container", "LHA/LZH archive", 85, "application/x-lha",
        {{"signature", "-lh?- marker at offset 2", 85}});
  }

  // Images (extra)
  if (starts_with(d, {'I', 'I', 0xBC})) {
    add(out, "image", "JPEG XR", 100, "image/jxr",
        {{"signature", "JXR magic", 100}});
  }
  if (starts_with(d, {'8', 'B', 'P', 'B'})) {
    add(out, "image", "Photoshop Large Document (PSB)", 100,
        "image/vnd.adobe.photoshop",
        {{"signature", "8BPB header", 100}});
  }
  if (starts_with_str(d, "FUJIFILMCCD-RAW")) {
    add(out, "image", "Fujifilm RAF raw", 100, "image/x-fuji-raf",
        {{"signature", "FUJIFILMCCD-RAW header", 100}});
  }

  // Monitor / hardware config
  if (starts_with(d, {0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00})) {
    add(out, "config", "EDID monitor descriptor", 100, "",
        {{"signature", "EDID fixed preamble", 100}});
  }

  // Reverse engineering / tooling
  if (starts_with_str(d, "IDA1") || starts_with_str(d, "IDA2")) {
    add(out, "database", "IDA Pro database", 100, "",
        {{"signature", "IDA1/IDA2 header", 100}});
  }

  // Protocols
  if (starts_with(d, {0xf9, 0xbe, 0xb4, 0xd9})) {
    add(out, "blockchain", "Bitcoin block file (mainnet)", 100, "",
        {{"signature", "Bitcoin mainnet magic", 100}});
  }

  // Binary diffs / patches
  if (starts_with(d, {0xd6, 0xc3, 0xc4, 0x00}) ||
      starts_with(d, {0xd6, 0xc3, 0xc4, 0x01})) {
    add(out, "patch", "VCDIFF (RFC 3284)", 100,
        "application/vnd.vcdiff",
        {{"signature", "VCDIFF header", 100}});
  }

  // Office/open document (ODF detection beyond just ZIP)
  if (starts_with(d, {'P', 'K', 0x03, 0x04}) &&
      d.size() >= 60 &&
      starts_with_str(d, "mimetype", 30) &&
      std::memcmp(d.data() + 38, "application/vnd.oasis.opendocument.",
                  std::min<std::size_t>(d.size() - 38, 36)) == 0) {
    add(out, "document", "OpenDocument (ODT/ODS/ODP)", 90,
        "application/vnd.oasis.opendocument",
        {{"signature", "mimetype entry at ZIP offset 30", 90}});
  }

  // ======================================================================
  //  Tier-G additions: another 25 formats
  // ======================================================================

  // Disk + VM images
  if (starts_with_str(d, "vhdxfile")) {
    add(out, "disk-image", "Microsoft VHDX", 100, "",
        {{"signature", "vhdxfile header", 100}});
  }

  // Archives / compression
  if (starts_with(d, {'7', 'k', 'S', 't', 0xa5, 0x2f, 0x8f})) {
    add(out, "container", "zpaq", 100, "application/x-zpaq",
        {{"signature", "zpaq header", 100}});
  }

  // Patches / diffs
  if (starts_with_str(d, "BSDIFF40")) {
    add(out, "patch", "bsdiff v4", 100, "",
        {{"signature", "BSDIFF40 header", 100}});
  }
  if (starts_with(d, {'%', 'X', 'D', 'Z'})) {
    add(out, "patch", "xdelta3 (VCDIFF)", 100, "",
        {{"signature", "xdelta3 %XDZ header", 100}});
  }

  // Scientific data
  if (starts_with(d, {'C', 'D', 'F', 0x01}) ||
      starts_with(d, {'C', 'D', 'F', 0x02})) {
    add(out, "data", "NetCDF classic", 100, "application/x-netcdf",
        {{"signature", "CDF v1/v2 header", 100}});
  }
  if (starts_with(d, {0x0e, 0x03, 0x13, 0x01})) {
    add(out, "data", "HDF4", 100, "",
        {{"signature", "HDF4 header", 100}});
  }
  if (d.size() >= 128 &&
      std::memcmp(d.data(), "MATLAB 5.0 MAT-file", 19) == 0) {
    add(out, "data", "MATLAB MAT-file v5+", 100, "application/x-matlab",
        {{"signature", "MATLAB 5.0 MAT-file header", 100}});
  }

  // Crypto / keys / secrets
  if (starts_with_str(d, "age-encryption.org/v1\n")) {
    add(out, "crypto", "age encrypted file", 100, "",
        {{"signature", "age-encryption.org/v1 header", 100}});
  }
  if (starts_with_str(d, "PuTTY-User-Key-File-")) {
    add(out, "key", "PuTTY SSH private key (PPK)", 100, "",
        {{"signature", "PuTTY-User-Key-File header", 100}});
  }

  // Game ROMs / consoles
  if (d.size() >= 0x10f && starts_with_str(d, "SEGA MEGA DRIVE", 0x100)) {
    add(out, "game-rom", "Sega Mega Drive / Genesis ROM", 100, "",
        {{"signature", "SEGA MEGA DRIVE title at 0x100", 100}});
  }
  if (d.size() >= 0x10f && starts_with_str(d, "SEGA GENESIS", 0x100)) {
    add(out, "game-rom", "Sega Genesis ROM", 100, "",
        {{"signature", "SEGA GENESIS title at 0x100", 100}});
  }
  if (d.size() >= 0x1f && starts_with_str(d, "SEGA SEGASATURN", 0x10)) {
    add(out, "game-rom", "Sega Saturn disc", 100, "",
        {{"signature", "SEGA SEGASATURN at offset 0x10", 100}});
  }
  if (d.size() >= 0x20 && starts_with(d, {0xc2, 0x33, 0x9f, 0x3d}, 0x1c)) {
    add(out, "game-rom", "Nintendo GameCube disc image", 100, "",
        {{"signature", "GameCube magic at 0x1c", 100}});
  }
  if (d.size() >= 0x1c && starts_with(d, {0x5d, 0x1c, 0x9e, 0xa3}, 0x18)) {
    add(out, "game-rom", "Nintendo Wii disc image", 100, "",
        {{"signature", "Wii magic at 0x18", 100}});
  }
  if (d.size() >= 0x14 && starts_with_str(d, "NRO0", 0x10)) {
    add(out, "game-rom", "Nintendo Switch NRO homebrew", 100, "",
        {{"signature", "NRO0 header at offset 0x10", 100}});
  }
  if (d.size() >= 0x14 && starts_with_str(d, "AEXI", 0x10)) {
    // Some Switch dumps place AEXI (NSO3) further in; kept narrow.
    add(out, "game-rom", "Nintendo Switch NSO/AEXI", 85, "",
        {{"signature", "AEXI header at 0x10", 85}});
  }

  // Android runtime
  if (starts_with(d, {'v', 'd', 'e', 'x'})) {
    add(out, "bytecode", "Android VDEX (ART)", 100, "",
        {{"signature", "vdex header", 100}});
  }
  if (starts_with(d, {'o', 'a', 't', '\n'})) {
    add(out, "bytecode", "Android OAT (Optimized DEX)", 100, "",
        {{"signature", "oat\\n header", 100}});
  }
  if (starts_with(d, {'a', 'r', 't', '\n'})) {
    add(out, "bytecode", "Android ART image", 100, "",
        {{"signature", "art\\n header", 100}});
  }

  // Modding / game data
  if (starts_with_str(d, "ERF V1.0") || starts_with_str(d, "ERF V2.0") ||
      starts_with_str(d, "MOD V1.0") || starts_with_str(d, "HAK V1.0")) {
    add(out, "game-asset", "BioWare Aurora/NWN ERF resource", 100, "",
        {{"signature", "ERF / MOD / HAK header", 100}});
  }
  if (starts_with(d, {0x55, 0xaa, 0x12, 0x34})) {
    add(out, "game-asset", "Valve VPK", 95, "",
        {{"signature", "VPK signature", 95}});
  }

  // Fonts (more)
  if (starts_with(d, {0x01, 'f', 'c', 'p'})) {
    add(out, "font", "PCF bitmap font", 100, "application/x-font-pcf",
        {{"signature", "PCF header", 100}});
  }
  if (starts_with_str(d, "STARTFONT ")) {
    add(out, "font", "BDF bitmap font", 100, "application/x-font-bdf",
        {{"signature", "STARTFONT text header", 100}});
  }

  // DMG sparsebundle info plist is text, skipped; DMG body is at end.
  //
  // Bitcoin wallet.dat starts with a BDB (Berkeley DB) magic.
  if (starts_with(d, {0x00, 0x05, 0x31, 0x62}) ||
      starts_with(d, {0x62, 0x31, 0x05, 0x00})) {
    add(out, "database", "Berkeley DB (BDB)", 85, "application/x-berkeley-db",
        {{"signature", "BDB magic (either endianness)", 85},
         {"note", "used by old Bitcoin wallet.dat and many legacy apps", 0}});
  }
}

void add_entropy_notes(Report& r) {
  if (r.entropy > 7.5) {
    r.notes.push_back(
        "High entropy: data may be compressed, encrypted, packed, or otherwise "
        "binary-dense.");
  } else if (r.entropy < 2.0) {
    r.notes.push_back(
        "Very low entropy: data is highly repetitive or sparse.");
  }
}

Bytes load_capped(const std::filesystem::path& p, std::uintmax_t cap,
                  std::uintmax_t file_size, bool& truncated) {
  std::ifstream f(p, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open input: " + p.string());
  std::uintmax_t take = file_size;
  if (take > cap) {
    truncated = true;
    take = cap;
  }
  Bytes d;
  d.resize(static_cast<std::size_t>(take));
  if (take) f.read(reinterpret_cast<char*>(d.data()),
                   static_cast<std::streamsize>(take));
  return d;
}

std::string json_escape(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\b': o += "\\b"; break;
      case '\f': o += "\\f"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", unsigned(c));
          o += buf;
        } else {
          o += c;
        }
    }
  }
  return o;
}

}  // namespace

namespace {

void populate_from_window(Report& r, const Bytes& d, std::uintmax_t cap) {
  r.bytes_scanned = d.size();

  std::array<std::uint64_t, 256> cnt{};
  std::uint64_t printable = 0;
  for (unsigned char c : d) {
    ++cnt[c];
    if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) ++printable;
  }
  if (!d.empty()) {
    for (auto n : cnt) {
      if (n == 0) continue;
      double p = double(n) / double(d.size());
      r.entropy -= p * std::log2(p);
    }
    r.printable_ratio = double(printable) / double(d.size());
    auto it = std::max_element(cnt.begin(), cnt.end());
    r.dominant_byte = unsigned(std::distance(cnt.begin(), it));
    r.dominant_byte_count = *it;
  }

  detect_signatures(d, r.detections);

  if (r.detections.empty() && r.printable_ratio > 0.97) {
    add(r.detections, "text", "Plain / structured text", 85, "text/plain",
        {{"heuristic", "printable ratio > 0.97", 85}});
  }

  add_entropy_notes(r);
  if (r.detections.empty()) {
    r.notes.push_back(
        "No known signature matched. This is not proof that the format is "
        "unknown; inspect structure, entropy, strings and offsets next.");
  }
  if (r.truncated) {
    r.notes.push_back("Structural analysis was capped at " +
                      std::to_string(cap) +
                      " bytes; SHA-256 covers the whole file.");
  }
}

}  // namespace

Report analyze_bytes(const std::string& synthetic_name,
                     const std::vector<unsigned char>& data,
                     AnalyzeOptions opt) {
  Report r;
  r.path = synthetic_name;
  r.size = data.size();
  r.sha256 = sha256_bytes(data);
  Bytes window;
  if (data.size() > opt.max_bytes) {
    r.truncated = true;
    window.assign(data.begin(), data.begin() + opt.max_bytes);
  } else {
    window = data;
  }
  populate_from_window(r, window, opt.max_bytes);
  return r;
}

Report analyze(const std::filesystem::path& path, AnalyzeOptions opt) {
  Report r;
  r.path = path;
  std::error_code ec;
  r.size = std::filesystem::file_size(path, ec);
  if (ec) throw std::runtime_error("cannot stat input: " + path.string());

  r.sha256 = sha256_file(path);  // always full-file stream

  Bytes d = load_capped(path, opt.max_bytes, r.size, r.truncated);
  populate_from_window(r, d, opt.max_bytes);
  return r;
}

void print_report(const Report& r) {
  std::cout << "=== DIGITAL ARCHAEOLOGIST ===\n"
            << "file: " << r.path.string() << "\n"
            << "size: " << r.size << " bytes\n"
            << "sha256: " << r.sha256 << "\n"
            << "entropy: " << std::fixed << std::setprecision(4) << r.entropy
            << " / 8.0\n"
            << "printable_ratio: " << r.printable_ratio << "\n"
            << "bytes_scanned: " << r.bytes_scanned
            << (r.truncated ? "  (truncated)" : "") << "\n";
  if (r.detections.empty()) {
    std::cout << "detection: UNKNOWN / UNRESOLVED\n";
  } else {
    for (const auto& det : r.detections) {
      std::cout << "detection: " << det.format << " [" << det.confidence
                << "%] (" << det.category << ")";
      if (!det.mime.empty()) std::cout << "  mime=" << det.mime;
      std::cout << "\n";
      for (const auto& ev : det.evidence) {
        std::cout << "  + " << ev.label << ": " << ev.detail << " ("
                  << ev.weight << ")\n";
      }
    }
  }
  for (const auto& n : r.notes) std::cout << "note: " << n << "\n";
  if (!r.detections.empty() && r.detections.front().confidence == 100) {
    std::cout
        << "\nCOMPLETE ANSWER FOUND (for the matched signature; structural "
           "completeness is not guaranteed).\n";
  }
}

void print_report_json(const Report& r) {
  std::ostringstream o;
  o << "{";
  o << "\"path\":\"" << json_escape(r.path.string()) << "\",";
  o << "\"size\":" << r.size << ",";
  o << "\"sha256\":\"" << r.sha256 << "\",";
  o << "\"entropy\":" << std::fixed << std::setprecision(6) << r.entropy
    << ",";
  o << "\"printable_ratio\":" << r.printable_ratio << ",";
  o << "\"bytes_scanned\":" << r.bytes_scanned << ",";
  o << "\"truncated\":" << (r.truncated ? "true" : "false") << ",";
  o << "\"dominant_byte\":" << r.dominant_byte << ",";
  o << "\"dominant_byte_count\":" << r.dominant_byte_count << ",";
  o << "\"detections\":[";
  for (std::size_t i = 0; i < r.detections.size(); ++i) {
    const auto& det = r.detections[i];
    if (i) o << ",";
    o << "{\"category\":\"" << json_escape(det.category) << "\","
      << "\"format\":\"" << json_escape(det.format) << "\","
      << "\"confidence\":" << det.confidence << ","
      << "\"mime\":\"" << json_escape(det.mime) << "\","
      << "\"evidence\":[";
    for (std::size_t j = 0; j < det.evidence.size(); ++j) {
      const auto& ev = det.evidence[j];
      if (j) o << ",";
      o << "{\"label\":\"" << json_escape(ev.label) << "\","
        << "\"detail\":\"" << json_escape(ev.detail) << "\","
        << "\"weight\":" << ev.weight << "}";
    }
    o << "]}";
  }
  o << "],\"notes\":[";
  for (std::size_t i = 0; i < r.notes.size(); ++i) {
    if (i) o << ",";
    o << "\"" << json_escape(r.notes[i]) << "\"";
  }
  o << "]}";
  std::cout << o.str() << "\n";
}

}  // namespace da
