// Micro-benchmark for the full analyzer pipeline across a representative
// set of input sizes and formats.

#include <cstring>
#include <random>
#include <vector>

#include "analyzer.hpp"
#include "bench_util.hpp"

namespace {

std::vector<unsigned char> make_random(std::size_t n, std::uint32_t seed) {
  std::mt19937 rng(seed);
  std::vector<unsigned char> v(n);
  for (std::size_t i = 0; i < n; ++i) v[i] = (unsigned char)(rng() & 0xff);
  return v;
}

std::vector<unsigned char> make_png_padded(std::size_t total) {
  std::vector<unsigned char> v(total, 0);
  const unsigned char png[] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
  if (total >= sizeof(png)) std::memcpy(v.data(), png, sizeof(png));
  return v;
}

}  // namespace

int main() {
  constexpr std::size_t KB = 1024;
  constexpr std::size_t MB = 1024 * 1024;

  struct Case {
    const char* name;
    std::vector<unsigned char> data;
    std::size_t iters;
  };
  std::vector<Case> cases = {
      {"random 1 KiB", make_random(1 * KB, 1), 5000},
      {"random 64 KiB", make_random(64 * KB, 2), 500},
      {"random 1 MiB", make_random(1 * MB, 3), 50},
      {"random 16 MiB", make_random(16 * MB, 4), 5},
      {"PNG-signatured 1 KiB", make_png_padded(1 * KB), 5000},
      {"PNG-signatured 1 MiB", make_png_padded(1 * MB), 50},
  };

  std::printf("%-32s %7s   %8s          %10s %8s\n", "case", "iters",
              "wall", "us/op", "MB/s");
  for (const auto& c : cases) {
    da_bench::bench(
        c.name, c.iters,
        [&] { (void)da::analyze_bytes(c.name, c.data); },
        c.data.size());
  }
  return 0;
}
