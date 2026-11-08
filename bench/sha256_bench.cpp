// SHA-256 throughput at several block sizes.

#include <vector>

#include "bench_util.hpp"
#include "hashing.hpp"

int main() {
  constexpr std::size_t KB = 1024;
  constexpr std::size_t MB = 1024 * 1024;

  std::printf("%-32s %7s   %8s          %10s %8s\n", "case", "iters",
              "wall", "us/op", "MB/s");

  struct Case {
    const char* name;
    std::size_t size;
    std::size_t iters;
  };
  Case cases[] = {
      {"sha256 1 KiB", 1 * KB, 100000},
      {"sha256 64 KiB", 64 * KB, 2000},
      {"sha256 1 MiB", 1 * MB, 200},
      {"sha256 16 MiB", 16 * MB, 10},
  };

  for (const auto& c : cases) {
    std::vector<unsigned char> buf(c.size, 0xab);
    da_bench::bench(
        c.name, c.iters,
        [&] { (void)da::sha256_bytes(buf); }, c.size);
  }
  return 0;
}
