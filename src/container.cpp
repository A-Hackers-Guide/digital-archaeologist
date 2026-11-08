#include "container.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace da {
namespace {

using Bytes = std::vector<unsigned char>;

inline std::uint16_t u16le(const Bytes& d, std::size_t o) {
  if (o + 2 > d.size()) return 0;
  return std::uint16_t(d[o]) | (std::uint16_t(d[o + 1]) << 8);
}
inline std::uint32_t u32le(const Bytes& d, std::size_t o) {
  if (o + 4 > d.size()) return 0;
  return std::uint32_t(d[o]) | (std::uint32_t(d[o + 1]) << 8) |
         (std::uint32_t(d[o + 2]) << 16) | (std::uint32_t(d[o + 3]) << 24);
}

bool starts_with(const Bytes& d, std::initializer_list<unsigned char> s,
                 std::size_t off = 0) {
  if (off + s.size() > d.size()) return false;
  return std::equal(s.begin(), s.end(), d.begin() + off);
}

// --- ZIP ---
//
// Prefer walking the central directory so we see every entry (including
// ones whose local headers have been stripped). Find the End-Of-Central-
// Directory record in the last 64 KiB of the file, then walk its entries.
bool list_zip(const Bytes& d, ContainerListing& out) {
  if (!starts_with(d, {'P', 'K', 0x03, 0x04}) &&
      !starts_with(d, {'P', 'K', 0x05, 0x06})) return false;
  out.format = "ZIP";
  if (d.size() < 22) return true;

  // Scan for EOCD signature 'PK\x05\x06' within the last 65557 bytes.
  std::size_t search_start = (d.size() > 65557) ? d.size() - 65557 : 0;
  std::size_t eocd = std::string::npos;
  for (std::size_t i = d.size() - 22; i >= search_start; --i) {
    if (d[i] == 'P' && d[i + 1] == 'K' && d[i + 2] == 0x05 &&
        d[i + 3] == 0x06) {
      eocd = i;
      break;
    }
    if (i == 0) break;
  }
  if (eocd == std::string::npos) return true;
  std::uint16_t n = u16le(d, eocd + 10);                // total entries
  std::uint32_t cd_size = u32le(d, eocd + 12);
  std::uint32_t cd_off = u32le(d, eocd + 16);
  if (cd_off + cd_size > d.size()) { out.truncated = true; return true; }

  std::size_t p = cd_off;
  for (std::uint16_t i = 0; i < n && p + 46 <= cd_off + cd_size; ++i) {
    if (!(d[p] == 'P' && d[p + 1] == 'K' && d[p + 2] == 0x01 &&
          d[p + 3] == 0x02)) break;
    std::uint32_t crc = u32le(d, p + 16);
    std::uint32_t usz = u32le(d, p + 24);
    std::uint16_t nlen = u16le(d, p + 28);
    std::uint16_t xlen = u16le(d, p + 30);
    std::uint16_t clen = u16le(d, p + 32);
    std::uint32_t local = u32le(d, p + 42);
    if (p + 46 + nlen > d.size()) { out.truncated = true; break; }
    ContainerEntry e;
    e.path.assign(reinterpret_cast<const char*>(d.data() + p + 46), nlen);
    e.size = usz;
    e.crc32 = crc;
    e.offset = local;
    out.entries.push_back(std::move(e));
    p += 46 + nlen + xlen + clen;
    if (out.entries.size() >= 10000) { out.truncated = true; break; }
  }
  return true;
}

// --- TAR (POSIX ustar) ---
//
// Every entry is a 512-byte header followed by its payload rounded up to
// 512. The filename is NUL-terminated at offset 0, size is octal at 124.
bool list_tar(const Bytes& d, ContainerListing& out) {
  if (d.size() < 512) return false;
  // ustar signature is at offset 257; also accept pre-ustar if first block
  // looks like a plausible filename followed by a small octal size.
  bool ustar = d.size() >= 265 &&
               std::memcmp(d.data() + 257, "ustar", 5) == 0;
  if (!ustar) return false;
  out.format = "TAR";

  std::size_t p = 0;
  while (p + 512 <= d.size()) {
    // All-zero block marks end of archive.
    bool zero = true;
    for (int i = 0; i < 100; ++i) {
      if (d[p + i] != 0) { zero = false; break; }
    }
    if (zero) break;

    // Filename is up to 100 bytes, NUL-terminated.
    std::size_t nl = 0;
    while (nl < 100 && d[p + nl] != 0) ++nl;
    ContainerEntry e;
    e.path.assign(reinterpret_cast<const char*>(d.data() + p), nl);
    // Octal size at offset 124, 12 bytes.
    std::uint64_t sz = 0;
    for (int i = 0; i < 11 && d[p + 124 + i] != 0; ++i) {
      char c = char(d[p + 124 + i]);
      if (c < '0' || c > '7') { sz = 0; break; }
      sz = sz * 8 + std::uint64_t(c - '0');
    }
    e.size = sz;
    e.offset = p + 512;
    out.entries.push_back(std::move(e));

    std::size_t payload = (sz + 511) & ~std::size_t(511);
    p += 512 + payload;
    if (out.entries.size() >= 10000) { out.truncated = true; break; }
  }
  return true;
}

// --- GZIP ---
//
// Read the member header: flags at offset 3, mtime at offset 4, optional
// FNAME field after offset 10 when bit 3 of flags is set.
bool list_gzip(const Bytes& d, ContainerListing& out) {
  if (d.size() < 10 || d[0] != 0x1f || d[1] != 0x8b) return false;
  out.format = "GZIP";
  std::uint8_t flg = d[3];
  std::size_t p = 10;
  if (flg & 0x04) {  // FEXTRA
    if (p + 2 > d.size()) return true;
    std::uint16_t xlen = u16le(d, p);
    p += 2 + xlen;
  }
  if (flg & 0x08) {  // FNAME
    std::size_t start = p;
    while (p < d.size() && d[p] != 0) ++p;
    out.inner_name.assign(reinterpret_cast<const char*>(d.data() + start),
                          p - start);
    if (p < d.size()) ++p;  // skip NUL
  }
  // Carry mtime over to a single entry describing the compressed payload.
  ContainerEntry e;
  e.path = out.inner_name.empty() ? std::string("<deflate-stream>")
                                  : out.inner_name;
  e.mtime = u32le(d, 4);
  out.entries.push_back(std::move(e));
  return true;
}

}  // namespace

ContainerListing list_container(const Bytes& data) {
  ContainerListing out;
  if (list_zip(data, out)) return out;
  if (list_tar(data, out)) return out;
  if (list_gzip(data, out)) return out;
  return out;
}

}  // namespace da
