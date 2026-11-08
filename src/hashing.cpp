#include "hashing.hpp"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace da {
namespace {

constexpr std::uint32_t kInit[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

constexpr std::uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline std::uint32_t rotr(std::uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}

}  // namespace

Sha256::Sha256() {
  for (int i = 0; i < 8; ++i) h_[i] = kInit[i];
}

void Sha256::transform(const unsigned char* block) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (std::uint32_t(block[i * 4]) << 24) |
           (std::uint32_t(block[i * 4 + 1]) << 16) |
           (std::uint32_t(block[i * 4 + 2]) << 8) |
           std::uint32_t(block[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
  std::uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
  for (int i = 0; i < 64; ++i) {
    std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    std::uint32_t ch = (e & f) ^ ((~e) & g);
    std::uint32_t t1 = hh + S1 + ch + kK[i] + w[i];
    std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    std::uint32_t t2 = S0 + maj;
    hh = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += hh;
}

void Sha256::update(const unsigned char* data, std::size_t len) {
  bits_ += std::uint64_t(len) * 8;
  while (len > 0) {
    std::size_t take = std::min<std::size_t>(64 - buf_len_, len);
    std::memcpy(buf_.data() + buf_len_, data, take);
    buf_len_ += take;
    data += take;
    len -= take;
    if (buf_len_ == 64) {
      transform(buf_.data());
      buf_len_ = 0;
    }
  }
}

std::string Sha256::finalize() {
  // Snapshot the message length BEFORE we add padding (padding bytes don't
  // count as message content).
  std::uint64_t total_bits = bits_;

  // 0x80 trailer
  buf_[buf_len_++] = 0x80;

  // If the trailer landed past the length field's slot, pad out this block
  // and start a fresh one for the length.
  if (buf_len_ > 56) {
    while (buf_len_ < 64) buf_[buf_len_++] = 0;
    transform(buf_.data());
    buf_len_ = 0;
  }
  while (buf_len_ < 56) buf_[buf_len_++] = 0;

  // 64-bit big-endian length
  for (int i = 7; i >= 0; --i)
    buf_[buf_len_++] = (unsigned char)(total_bits >> (i * 8));
  transform(buf_.data());
  buf_len_ = 0;

  std::ostringstream o;
  o << std::hex << std::setfill('0');
  for (auto v : h_) o << std::setw(8) << v;
  return o.str();
}

std::string sha256_bytes(const std::vector<unsigned char>& data) {
  Sha256 h;
  if (!data.empty()) h.update(data.data(), data.size());
  return h.finalize();
}

std::string sha256_file(const std::filesystem::path& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open for hashing: " + path.string());
  Sha256 h;
  constexpr std::size_t kChunk = 1 << 16;  // 64 KiB
  std::vector<unsigned char> buf(kChunk);
  while (f) {
    f.read(reinterpret_cast<char*>(buf.data()), kChunk);
    std::streamsize got = f.gcount();
    if (got > 0) h.update(buf.data(), std::size_t(got));
  }
  return h.finalize();
}

}  // namespace da
