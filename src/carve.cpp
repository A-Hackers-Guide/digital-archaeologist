#include "carve.hpp"

#include <cstring>
#include <fstream>
#include <stdexcept>

namespace da {
namespace {

struct Signature {
  const char* name;
  const char* ext;
  std::vector<unsigned char> magic;
};

// Keep the list short: formats where runaway false-positive carving would
// be useless. These are the ones with long, distinctive magic bytes.
const Signature kSigs[] = {
    {"ZIP", "zip", {'P', 'K', 0x03, 0x04}},
    {"GZIP", "gz", {0x1f, 0x8b, 0x08}},
    {"PNG", "png", {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}},
    {"JPEG", "jpg", {0xff, 0xd8, 0xff}},
    {"PDF", "pdf", {0x25, 0x50, 0x44, 0x46, 0x2d}},
    {"ELF", "elf", {0x7f, 'E', 'L', 'F'}},
    {"MZ", "exe", {'M', 'Z'}},
    {"7z", "7z", {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
    {"RAR", "rar", {'R', 'a', 'r', '!', 0x1a, 0x07}},
    {"BZIP2", "bz2", {'B', 'Z', 'h'}},
    {"XZ", "xz", {0xfd, '7', 'z', 'X', 'Z', 0x00}},
    {"OggS", "ogg", {'O', 'g', 'g', 'S'}},
    {"MATROSKA", "mkv", {0x1a, 0x45, 0xdf, 0xa3}},
    {"SQLite", "sqlite", {'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r',
                           'm', 'a', 't', ' ', '3', 0}},
};

bool match_at(const std::vector<unsigned char>& d, std::size_t p,
              const std::vector<unsigned char>& m) {
  if (p + m.size() > d.size()) return false;
  return std::memcmp(d.data() + p, m.data(), m.size()) == 0;
}

std::vector<std::pair<std::size_t, int>> all_hits(
    const std::vector<unsigned char>& d) {
  std::vector<std::pair<std::size_t, int>> hits;
  for (std::size_t i = 0; i < d.size(); ++i) {
    for (std::size_t s = 0; s < sizeof(kSigs) / sizeof(kSigs[0]); ++s) {
      if (match_at(d, i, kSigs[s].magic)) {
        hits.push_back({i, int(s)});
        break;
      }
    }
  }
  return hits;
}

}  // namespace

std::vector<Carved> carve(const std::vector<unsigned char>& data,
                          const std::filesystem::path& out_dir) {
  std::error_code ec;
  std::filesystem::create_directories(out_dir, ec);
  if (ec) throw std::runtime_error("cannot create carve dir: " + ec.message());

  auto hits = all_hits(data);
  std::vector<Carved> out;
  for (std::size_t h = 0; h < hits.size(); ++h) {
    auto [offset, sig_idx] = hits[h];
    std::size_t next = (h + 1 < hits.size()) ? hits[h + 1].first : data.size();
    std::size_t len = next - offset;
    char name[64];
    std::snprintf(name, sizeof(name), "%08zx.%s", offset, kSigs[sig_idx].ext);
    auto p = out_dir / name;
    std::ofstream f(p, std::ios::binary);
    if (!f) continue;
    f.write(reinterpret_cast<const char*>(data.data() + offset),
            std::streamsize(len));
    Carved c;
    c.offset = offset;
    c.length = len;
    c.format = kSigs[sig_idx].name;
    c.out = p;
    out.push_back(std::move(c));
  }
  return out;
}

}  // namespace da
