// Detection tests. Writes tiny fixture files to a temp dir and asserts the
// analyzer identifies them correctly. No external binary blobs; everything
// is produced from inline bytes so the tests build and run on any platform.

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "analyzer.hpp"

namespace fs = std::filesystem;

static fs::path g_tmp;

static fs::path write_fixture(const std::string& name,
                              const std::vector<unsigned char>& bytes) {
  fs::path p = g_tmp / name;
  std::ofstream f(p, std::ios::binary);
  if (!f) {
    std::cerr << "cannot write fixture " << p << "\n";
    std::exit(2);
  }
  if (!bytes.empty())
    f.write(reinterpret_cast<const char*>(bytes.data()),
            std::streamsize(bytes.size()));
  return p;
}

static bool detected(const da::Report& r, const std::string& format) {
  for (const auto& d : r.detections)
    if (d.format.find(format) != std::string::npos) return true;
  return false;
}

static int g_failures = 0;
static void expect_detect(const std::string& fixture,
                          const std::vector<unsigned char>& bytes,
                          const std::string& expected_format) {
  auto p = write_fixture(fixture, bytes);
  auto r = da::analyze(p);
  if (!detected(r, expected_format)) {
    std::cerr << "FAIL: " << fixture << " expected format containing \""
              << expected_format << "\"; got:";
    for (const auto& d : r.detections) std::cerr << "  [" << d.format << "]";
    std::cerr << "\n";
    ++g_failures;
  }
}

static std::vector<unsigned char> pad(std::vector<unsigned char> head,
                                      std::size_t total,
                                      unsigned char fill = 0) {
  if (head.size() < total) head.resize(total, fill);
  return head;
}

int main() {
  g_tmp = fs::temp_directory_path() / "da_detect_test";
  fs::create_directories(g_tmp);

  // Executables
  expect_detect("mz.bin", {'M', 'Z', 0, 0, 0, 0}, "PE");
  expect_detect("elf.bin", {0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, "ELF");
  expect_detect("macho_le64.bin", {0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1},
                "Mach-O");
  expect_detect("macho_be64.bin", {0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 7},
                "Mach-O");

  // Documents
  expect_detect("doc.pdf",
                {0x25, 0x50, 0x44, 0x46, 0x2d, '1', '.', '7', '\n'},
                "PDF");

  // Images
  expect_detect(
      "img.png",
      {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13},
      "PNG");
  expect_detect("img.jpg", {0xff, 0xd8, 0xff, 0xe0, 0, 16, 'J', 'F', 'I', 'F'},
                "JPEG");
  expect_detect("img.gif",
                {'G', 'I', 'F', '8', '9', 'a', 1, 0, 1, 0}, "GIF");
  expect_detect("img.bmp",
                pad({'B', 'M', 0x3e, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0}, 16),
                "BMP");

  // Archives / compression
  expect_detect("a.zip", {'P', 'K', 0x03, 0x04, 0x14, 0}, "ZIP");
  expect_detect("a.gz", {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0}, "GZIP");
  expect_detect("a.bz2", {'B', 'Z', 'h', '9', 0x31, 0x41, 0x59, 0x26}, "BZIP2");
  expect_detect("a.xz",
                {0xfd, '7', 'z', 'X', 'Z', 0x00, 0, 4, 0xe6, 0xd6, 0xb4, 0x46},
                "XZ");
  expect_detect("a.7z",
                {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4}, "7-Zip");
  expect_detect("a.rar",
                {'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, "RAR");

  // TAR ustar at offset 257
  {
    std::vector<unsigned char> tar(512, 0);
    const char* ustar = "ustar\0";
    std::memcpy(tar.data() + 257, ustar, 6);
    expect_detect("a.tar", tar, "TAR");
  }

  // Audio
  expect_detect("a.mp3",
                {'I', 'D', '3', 3, 0, 0, 0, 0, 0, 0x0a}, "MP3");
  {
    std::vector<unsigned char> wav(44, 0);
    std::memcpy(wav.data(), "RIFF", 4);
    wav[4] = 36;  // size
    std::memcpy(wav.data() + 8, "WAVE", 4);
    expect_detect("a.wav", wav, "WAV");
  }

  // Database
  {
    std::vector<unsigned char> sqlite(100, 0);
    std::memcpy(sqlite.data(), "SQLite format 3\0", 16);
    expect_detect("a.sqlite", sqlite, "SQLite");
  }

  // Filesystems
  {
    // HFS+ signature H+ at offset 1024
    std::vector<unsigned char> hfs(2048, 0);
    hfs[1024] = 'H';
    hfs[1025] = '+';
    expect_detect("hfsplus.img", hfs, "HFS+");
  }
  {
    // ext superblock magic 0xEF53 at 0x438
    std::vector<unsigned char> ext(0x500, 0);
    ext[0x438] = 0x53;
    ext[0x439] = 0xef;
    expect_detect("ext.img", ext, "ext");
  }
  {
    // GPT: 55 AA at offset 510, "EFI PART" at offset 512
    std::vector<unsigned char> gpt(1024, 0);
    gpt[510] = 0x55;
    gpt[511] = 0xaa;
    std::memcpy(gpt.data() + 512, "EFI PART", 8);
    expect_detect("gpt.img", gpt, "GPT");
  }
  {
    // ISO 9660 primary volume descriptor at offset 0x8001
    std::vector<unsigned char> iso(0x8010, 0);
    std::memcpy(iso.data() + 0x8001, "CD001", 5);
    expect_detect("a.iso", iso, "ISO 9660");
  }
  {
    // SquashFS magic
    std::vector<unsigned char> sq = {'h', 's', 'q', 's', 1, 0, 0, 0};
    expect_detect("a.squashfs", sq, "SquashFS");
  }

  // Text fallback
  {
    std::string hello = "hello world, this is just plain text!\n";
    std::vector<unsigned char> b(hello.begin(), hello.end());
    expect_detect("a.txt", b, "text");
  }

  // --- Tier B additions ---
  expect_detect("a.tiff_le", {'I', 'I', 0x2a, 0x00, 0x08, 0, 0, 0}, "TIFF");
  expect_detect("a.tiff_be", {'M', 'M', 0x00, 0x2a, 0, 0, 0, 0x08}, "TIFF");
  {
    std::vector<unsigned char> webp = {'R', 'I', 'F', 'F', 0x1a, 0, 0, 0,
                                        'W', 'E', 'B', 'P', 'V', 'P', '8', 'L'};
    expect_detect("a.webp", webp, "WebP");
  }
  {
    std::vector<unsigned char> heic = {0, 0, 0, 0x18, 'f', 't', 'y', 'p',
                                        'h', 'e', 'i', 'c', 0, 0, 0, 0};
    expect_detect("a.heic", heic, "HEIF/HEIC");
  }
  {
    std::vector<unsigned char> avif = {0, 0, 0, 0x18, 'f', 't', 'y', 'p',
                                        'a', 'v', 'i', 'f', 0, 0, 0, 0};
    expect_detect("a.avif", avif, "AVIF");
  }
  {
    std::vector<unsigned char> mp4 = {0, 0, 0, 0x18, 'f', 't', 'y', 'p',
                                       'm', 'p', '4', '2', 0, 0, 0, 0};
    expect_detect("a.mp4", mp4, "MP4");
  }
  expect_detect("a.psd", {'8', 'B', 'P', 'S', 0, 1, 0, 0, 0, 0, 0, 0}, "PSD");
  expect_detect("a.exr", {0x76, 0x2f, 0x31, 0x01, 2, 0, 0, 0}, "OpenEXR");
  expect_detect("a.ico", {0x00, 0x00, 0x01, 0x00, 1, 0, 16, 16}, "ICO");
  expect_detect("a.woff", {'w', 'O', 'F', 'F', 0, 1, 0, 0}, "WOFF");
  expect_detect("a.woff2", {'w', 'O', 'F', '2', 0, 1, 0, 0}, "WOFF2");
  expect_detect("a.otf", {'O', 'T', 'T', 'O', 0, 1, 0, 0}, "OTF");
  expect_detect("a.flac", {'f', 'L', 'a', 'C', 0, 0, 0, 0x22}, "FLAC");
  expect_detect("a.ogg", {'O', 'g', 'g', 'S', 0, 2, 0, 0, 0, 0, 0, 0}, "Ogg");
  expect_detect("a.mid", {'M', 'T', 'h', 'd', 0, 0, 0, 6}, "MIDI");
  {
    std::vector<unsigned char> aiff = {'F', 'O', 'R', 'M', 0, 0, 0, 0x26,
                                        'A', 'I', 'F', 'F'};
    expect_detect("a.aiff", aiff, "AIFF");
  }
  expect_detect("a.mkv", {0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81},
                "Matroska");
  expect_detect("a.lz4", {0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82}, "LZ4");
  expect_detect("a.zst", {0x28, 0xb5, 0x2f, 0xfd, 0x24, 0, 0, 0}, "Zstandard");
  expect_detect("a.cab", {'M', 'S', 'C', 'F', 0, 0, 0, 0}, "CAB");
  expect_detect("a.rpm",
                {0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0, 0, 0}, "RPM");
  {
    std::vector<unsigned char> deb = {'!', '<', 'a', 'r', 'c', 'h', '>', '\n',
                                       'd', 'e', 'b', 'i', 'a', 'n', '-',
                                       'b', 'i', 'n', 'a', 'r', 'y'};
    expect_detect("a.deb", deb, "Debian");
  }
  expect_detect("a.cfb",
                {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, "CFBF");
  expect_detect("a.ps", {'%', '!', 'P', 'S', '-', 'A', 'd', 'o', 'b', 'e'},
                "PostScript");
  expect_detect("a.wasm",
                {0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, "WebAssembly");
  expect_detect("a.dex", {'d', 'e', 'x', '\n', '0', '3', '5', 0}, "Dalvik");
  {
    std::vector<unsigned char> boot(16, 0);
    std::memcpy(boot.data(), "ANDROID!", 8);
    expect_detect("boot.img", boot, "Android boot");
  }
  expect_detect("a.simg", {0x3a, 0xff, 0x26, 0xed, 1, 0, 0, 0}, "Android sparse");
  expect_detect("a.dtb", {0xd0, 0x0d, 0xfe, 0xed, 0, 0, 0, 0x20}, "Device Tree");
  expect_detect("a.nes", {'N', 'E', 'S', 0x1a, 0x10, 0x10, 0, 0}, "iNES");
  {
    std::vector<unsigned char> wad = {'I', 'W', 'A', 'D', 2, 0, 0, 0,
                                       12, 0, 0, 0};
    expect_detect("a.wad", wad, "WAD");
  }
  {
    std::vector<unsigned char> pcap = {0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0,
                                        0, 0, 0, 0};
    expect_detect("a.pcap", pcap, "pcap");
  }
  expect_detect("a.pcapng",
                {0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0}, "PCAPNG");
  expect_detect("a.crx", {'C', 'r', '2', '4', 3, 0, 0, 0}, "CRX");
  {
    std::string pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r";
    std::vector<unsigned char> b(pem.begin(), pem.end());
    expect_detect("id_ed25519", b, "OpenSSH");
  }
  {
    std::string pem = "-----BEGIN CERTIFICATE-----\nMIIDXT";
    std::vector<unsigned char> b(pem.begin(), pem.end());
    expect_detect("cert.pem", b, "PEM");
  }
  {
    std::string salt = "Salted__abcdefgh" + std::string(8, 0);
    std::vector<unsigned char> b(salt.begin(), salt.end());
    expect_detect("enc.bin", b, "OpenSSL");
  }
  expect_detect("a.npy",
                {0x93, 'N', 'U', 'M', 'P', 'Y', 1, 0}, "NumPy");
  expect_detect("a.parquet",
                {'P', 'A', 'R', '1', 0, 0, 0, 0}, "Parquet");
  {
    std::string sh = "#!/usr/bin/env python3\nprint('hi')\n";
    std::vector<unsigned char> b(sh.begin(), sh.end());
    expect_detect("a.sh", b, "Script");
  }
  expect_detect("a.xfs", {'X', 'F', 'S', 'B', 0, 0, 10, 0, 0, 0, 0, 0}, "XFS");
  expect_detect("a.qcow2", {'Q', 'F', 'I', 0xfb, 0, 0, 0, 3}, "QCOW2");
  expect_detect("a.vmdk", {'K', 'D', 'M', 'V', 1, 0, 0, 0}, "VMDK");

  // Report integrity: sha256 of empty file is the well-known constant.
  {
    auto p = write_fixture("empty.bin", {});
    auto r = da::analyze(p);
    const std::string empty_sha =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if (r.sha256 != empty_sha) {
      std::cerr << "FAIL: empty sha256 = " << r.sha256 << "\n";
      ++g_failures;
    }
  }

  if (g_failures) {
    std::cerr << g_failures << " failure(s)\n";
    return 1;
  }
  std::cout << "all detection tests passed\n";
  return 0;
}
