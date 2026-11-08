// Container-walk tests. Build a minimal (but valid) ZIP, TAR, and GZIP in
// memory, run list_container, and assert we get the expected entries out.

#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "container.hpp"

namespace {

int fails = 0;

void put_u16le(std::vector<unsigned char>& v, std::uint16_t x) {
  v.push_back((unsigned char)(x & 0xff));
  v.push_back((unsigned char)((x >> 8) & 0xff));
}
void put_u32le(std::vector<unsigned char>& v, std::uint32_t x) {
  put_u16le(v, (std::uint16_t)(x & 0xffff));
  put_u16le(v, (std::uint16_t)((x >> 16) & 0xffff));
}

// Build a minimal single-entry stored ZIP for file name `name` holding one
// byte 'x'. CRC32 of 'x' is 0x8CDC1683.
std::vector<unsigned char> make_zip(const std::string& name) {
  std::vector<unsigned char> v;
  // Local file header
  v.insert(v.end(), {'P', 'K', 0x03, 0x04});
  put_u16le(v, 20);            // version needed
  put_u16le(v, 0);             // flags
  put_u16le(v, 0);             // method = stored
  put_u16le(v, 0);             // mtime
  put_u16le(v, 0);             // mdate
  put_u32le(v, 0x8CDC1683);    // crc32 of "x"
  put_u32le(v, 1);             // compressed size
  put_u32le(v, 1);             // uncompressed size
  put_u16le(v, (std::uint16_t)name.size());
  put_u16le(v, 0);             // extra len
  v.insert(v.end(), name.begin(), name.end());
  v.push_back('x');

  std::size_t cd_off = v.size();

  // Central directory
  v.insert(v.end(), {'P', 'K', 0x01, 0x02});
  put_u16le(v, 20);            // version made by
  put_u16le(v, 20);            // version needed
  put_u16le(v, 0);             // flags
  put_u16le(v, 0);             // method
  put_u16le(v, 0);             // mtime
  put_u16le(v, 0);             // mdate
  put_u32le(v, 0x8CDC1683);
  put_u32le(v, 1);
  put_u32le(v, 1);
  put_u16le(v, (std::uint16_t)name.size());
  put_u16le(v, 0);             // extra len
  put_u16le(v, 0);             // comment len
  put_u16le(v, 0);             // disk
  put_u16le(v, 0);             // internal attrs
  put_u32le(v, 0);             // external attrs
  put_u32le(v, 0);             // local header offset
  v.insert(v.end(), name.begin(), name.end());

  std::size_t cd_size = v.size() - cd_off;

  // EOCD
  v.insert(v.end(), {'P', 'K', 0x05, 0x06});
  put_u16le(v, 0);             // disk
  put_u16le(v, 0);             // central dir disk
  put_u16le(v, 1);             // entries on disk
  put_u16le(v, 1);             // total entries
  put_u32le(v, (std::uint32_t)cd_size);
  put_u32le(v, (std::uint32_t)cd_off);
  put_u16le(v, 0);             // comment len
  return v;
}

// Build a tar with two ustar entries: "a.txt" (size 1) and "b.txt" (size 2).
std::vector<unsigned char> make_tar() {
  auto block = [](const std::string& name, std::size_t size,
                  const std::string& payload) {
    std::vector<unsigned char> b(512, 0);
    std::memcpy(b.data(), name.c_str(),
                std::min<std::size_t>(99, name.size()));
    char sz[12];
    std::snprintf(sz, sizeof(sz), "%011o", unsigned(size));
    std::memcpy(b.data() + 124, sz, 11);
    std::memcpy(b.data() + 257, "ustar\0", 6);
    std::memcpy(b.data() + 263, "00", 2);
    std::vector<unsigned char> out = b;
    std::vector<unsigned char> payload_padded(((size + 511) / 512) * 512, 0);
    std::memcpy(payload_padded.data(), payload.data(), payload.size());
    out.insert(out.end(), payload_padded.begin(), payload_padded.end());
    return out;
  };
  std::vector<unsigned char> v;
  auto a = block("a.txt", 1, "A");
  auto b = block("b.txt", 2, "BC");
  v.insert(v.end(), a.begin(), a.end());
  v.insert(v.end(), b.begin(), b.end());
  v.insert(v.end(), 1024, 0);  // end-of-archive marker (two zero blocks)
  return v;
}

// Build a GZIP member with FNAME set to "payload.bin".
std::vector<unsigned char> make_gzip() {
  std::vector<unsigned char> v = {
      0x1f, 0x8b, 0x08, 0x08,     // id1 id2 compression flags
      0x00, 0x1c, 0xef, 0x5f,     // mtime (2021-01-01 UTC)
      0x00, 0x03,                 // xfl + os
  };
  const char* name = "payload.bin";
  v.insert(v.end(), name, name + std::strlen(name));
  v.push_back(0);
  // One byte of (fake) deflate data — we don't decode it.
  v.push_back(0x03);
  v.push_back(0x00);
  // Trailing CRC32 + ISIZE (any)
  v.insert(v.end(), 8, 0);
  return v;
}

}  // namespace

int main() {
  // ZIP
  {
    auto z = make_zip("hello.txt");
    auto l = da::list_container(z);
    if (l.format != "ZIP" || l.entries.size() != 1 ||
        l.entries[0].path != "hello.txt" ||
        l.entries[0].crc32 != 0x8CDC1683u ||
        l.entries[0].size != 1) {
      std::cerr << "FAIL: ZIP listing wrong\n";
      ++fails;
    }
  }

  // TAR
  {
    auto t = make_tar();
    auto l = da::list_container(t);
    if (l.format != "TAR" || l.entries.size() != 2 ||
        l.entries[0].path != "a.txt" || l.entries[0].size != 1 ||
        l.entries[1].path != "b.txt" || l.entries[1].size != 2) {
      std::cerr << "FAIL: TAR listing wrong, got " << l.entries.size()
                << " entries\n";
      for (const auto& e : l.entries)
        std::cerr << "  " << e.path << " size=" << e.size << "\n";
      ++fails;
    }
  }

  // GZIP
  {
    auto g = make_gzip();
    auto l = da::list_container(g);
    if (l.format != "GZIP" || l.inner_name != "payload.bin") {
      std::cerr << "FAIL: GZIP listing wrong, format=" << l.format
                << " inner=" << l.inner_name << "\n";
      ++fails;
    }
  }

  // Not a container → empty format, no entries.
  {
    std::vector<unsigned char> text(100, 'a');
    auto l = da::list_container(text);
    if (!l.format.empty() || !l.entries.empty()) {
      std::cerr << "FAIL: non-container returned non-empty listing\n";
      ++fails;
    }
  }

  if (fails) return 1;
  std::cout << "container tests passed\n";
  return 0;
}
