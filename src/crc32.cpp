#include "crc32.hpp"

#include <array>

namespace da {
namespace {

constexpr std::array<std::uint32_t, 256> build_table() {
  std::array<std::uint32_t, 256> t{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
    t[i] = c;
  }
  return t;
}

const std::array<std::uint32_t, 256> kTable = build_table();

}  // namespace

Crc32::Crc32() : state_(0xFFFFFFFFu) {}

void Crc32::update(const unsigned char* data, std::size_t len) {
  std::uint32_t c = state_;
  for (std::size_t i = 0; i < len; ++i)
    c = kTable[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
  state_ = c;
}

std::uint32_t Crc32::finalize() { return state_ ^ 0xFFFFFFFFu; }

std::uint32_t crc32_bytes(const std::vector<unsigned char>& data) {
  Crc32 c;
  if (!data.empty()) c.update(data.data(), data.size());
  return c.finalize();
}

}  // namespace da
