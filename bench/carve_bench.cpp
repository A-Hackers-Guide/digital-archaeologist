// Signature-carve sweep over mixed payloads.

#include <cstring>
#include <filesystem>
#include <random>
#include <vector>

#include "bench_util.hpp"
#include "carve.hpp"

namespace {

// Build a buffer that contains N interleaved recognised signatures separated
// by random bytes.
std::vector<unsigned char> mixed_buf(std::size_t signatures, std::size_t gap,
                                     std::uint32_t seed) {
  std::mt19937 rng(seed);
  std::vector<unsigned char> v;
  const unsigned char png[] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
  const unsigned char jpg[] = {0xff, 0xd8, 0xff, 0xe0};
  const unsigned char zip[] = {'P', 'K', 0x03, 0x04};
  const unsigned char* pats[] = {png, jpg, zip};
  const std::size_t lens[] = {sizeof(png), sizeof(jpg), sizeof(zip)};
  for (std::size_t i = 0; i < signatures; ++i) {
    for (std::size_t g = 0; g < gap; ++g) v.push_back((unsigned char)(rng() & 0xff));
    std::size_t p = i % 3;
    v.insert(v.end(), pats[p], pats[p] + lens[p]);
  }
  return v;
}

}  // namespace

int main() {
  std::printf("%-32s %7s   %8s          %10s %8s\n", "case", "iters",
              "wall", "us/op", "MB/s");
  auto out = std::filesystem::temp_directory_path() / "da_bench_carve_out";

  struct Case {
    const char* name;
    std::vector<unsigned char> buf;
    std::size_t iters;
  };
  Case cases[] = {
      {"carve 10 sigs, 1 KiB gaps", mixed_buf(10, 1024, 1), 2000},
      {"carve 100 sigs, 1 KiB gaps", mixed_buf(100, 1024, 2), 200},
      {"carve 10 sigs, 64 KiB gaps", mixed_buf(10, 64 * 1024, 3), 500},
  };
  for (auto& c : cases) {
    da_bench::bench(
        c.name, c.iters,
        [&] { (void)da::carve(c.buf, out); }, c.buf.size());
  }
  return 0;
}
