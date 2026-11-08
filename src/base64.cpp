#include "base64.hpp"

#include <array>
#include <cstdint>

namespace da {
namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

}  // namespace

std::string base64_encode(const std::vector<unsigned char>& d) {
  std::string out;
  out.reserve(((d.size() + 2) / 3) * 4);
  for (std::size_t i = 0; i < d.size(); i += 3) {
    std::uint32_t v = std::uint32_t(d[i]) << 16;
    if (i + 1 < d.size()) v |= std::uint32_t(d[i + 1]) << 8;
    if (i + 2 < d.size()) v |= std::uint32_t(d[i + 2]);
    out += kAlphabet[(v >> 18) & 0x3f];
    out += kAlphabet[(v >> 12) & 0x3f];
    out += (i + 1 < d.size()) ? kAlphabet[(v >> 6) & 0x3f] : '=';
    out += (i + 2 < d.size()) ? kAlphabet[v & 0x3f] : '=';
  }
  return out;
}

std::vector<unsigned char> base64_decode(const std::string& s) {
  std::array<int, 256> m{};
  m.fill(-1);
  for (int i = 0; i < 64; ++i) m[(unsigned char)kAlphabet[i]] = i;

  std::vector<unsigned char> out;
  std::uint32_t v = 0;
  int bits = -8;
  for (unsigned char c : s) {
    if (c == '=') break;
    int d = m[c];
    if (d < 0) continue;
    v = (v << 6) | std::uint32_t(d);
    bits += 6;
    if (bits >= 0) {
      out.push_back((unsigned char)((v >> bits) & 0xffu));
      bits -= 8;
    }
  }
  return out;
}

}  // namespace da
