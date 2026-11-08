#include <cstdio>
#include <iostream>
#include <vector>

#include "crc32.hpp"

int main() {
  int fails = 0;
  auto check = [&](const std::vector<unsigned char>& in, std::uint32_t want) {
    auto got = da::crc32_bytes(in);
    if (got != want) {
      std::fprintf(stderr, "FAIL: crc32 got 0x%08x want 0x%08x\n", got, want);
      ++fails;
    }
  };
  // Known CRC-32 (IEEE 802.3 / zlib) vectors.
  check({}, 0x00000000);
  check({'a'}, 0xE8B7BE43);
  check({'a', 'b', 'c'}, 0x352441C2);
  // 1 000 000 'a'
  {
    std::vector<unsigned char> a(1000000, 'a');
    check(a, 0xDC25BFBC);
  }
  // Streaming vs batched over an arbitrary payload.
  {
    std::vector<unsigned char> v;
    for (int i = 0; i < 4096; ++i) v.push_back((unsigned char)(i & 0xff));
    auto batched = da::crc32_bytes(v);
    da::Crc32 c;
    std::size_t off = 0, step = 13;
    while (off < v.size()) {
      std::size_t take = std::min(step, v.size() - off);
      c.update(v.data() + off, take);
      off += take;
    }
    if (batched != c.finalize()) {
      std::fprintf(stderr, "FAIL: streamed/batched crc32 mismatch\n");
      ++fails;
    }
  }
  if (fails) return 1;
  std::cout << "crc32 tests passed\n";
  return 0;
}
