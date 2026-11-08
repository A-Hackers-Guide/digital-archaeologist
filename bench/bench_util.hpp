// Tiny benchmarking harness. No third-party deps.
//
// Call `bench(label, iters, fn)` and it prints
//
//   label                 N iters, 123.4 ms total, 1.234 us / op, 456.78 MB/s
//
// Pass bytes_per_op if you want the MB/s column; else it's omitted.

#pragma once
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>

namespace da_bench {

inline void bench(const std::string& label, std::size_t iters,
                  const std::function<void()>& fn,
                  std::uint64_t bytes_per_op = 0) {
  using clock = std::chrono::steady_clock;
  auto start = clock::now();
  for (std::size_t i = 0; i < iters; ++i) fn();
  auto end = clock::now();
  auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
                .count();
  double per = double(ns) / double(iters);
  std::printf("%-32s %7zu iters, %8.2f ms total, %10.2f us/op",
              label.c_str(), iters, double(ns) / 1e6, per / 1000.0);
  if (bytes_per_op > 0) {
    double mbps = (double(iters) * double(bytes_per_op) / 1e6) /
                  (double(ns) / 1e9);
    std::printf(", %8.2f MB/s", mbps);
  }
  std::printf("\n");
}

}  // namespace da_bench
