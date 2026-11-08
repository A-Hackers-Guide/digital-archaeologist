# Benchmarks

Three micro-bench executables live under `bench/`. They're opt-in (nothing links libgoogle-benchmark or any other third-party dep — the harness is 30 lines of `std::chrono` under `bench/bench_util.hpp`), so you build them when you want them:

```bash
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DDA_BENCH=ON
cmake --build build-bench --parallel

./build-bench/bench/da_bench_analyze
./build-bench/bench/da_bench_sha256
./build-bench/bench/da_bench_carve
```

Each prints a table of `case / iters / wall / us-per-op / MB/s`.

## What each one covers

| Binary | What it measures |
|---|---|
| `da_bench_analyze` | The full `da::analyze_bytes` pipeline (SHA-256 + entropy + printable ratio + signature scan + JSON output) at 1 KiB / 64 KiB / 1 MiB / 16 MiB for random bytes **and** for PNG-signatured padded buffers (different hot paths — unknown vs. known). |
| `da_bench_sha256` | SHA-256 throughput on `0xab`-filled buffers at 1 KiB / 64 KiB / 1 MiB / 16 MiB — isolates the hasher from the rest of analyze. |
| `da_bench_carve` | Signature-based carver sweep over mixed PNG / JPEG / ZIP magics with 1 KiB and 64 KiB gaps and 10 or 100 embedded signatures. |

## Sample numbers

AppleClang 21 on Apple silicon, Release build, no sanitizers:

```
sha256 1 KiB                      100000 iters,       5.37 us/op,   190.55 MB/s
sha256 64 KiB                       2000 iters,     192.06 us/op,   341.22 MB/s
sha256 1 MiB                         200 iters,    2850.38 us/op,   367.87 MB/s
sha256 16 MiB                         10 iters,   54945.01 us/op,   305.35 MB/s
```

The 64 KiB → 1 MiB climb up to ~367 MB/s is where the inner loop amortises over the SHA-256 setup/finalise; the 16 MiB dip is cache-miss driven.

## Why no CI run

Micro-bench numbers from a GitHub runner swing by ~5-10× depending on the host, and comparing two runs on different hosts is meaningless. The bench binaries are for engineers running them on the same machine across commits, not for ranking releases.

## Adding a benchmark

1. Drop a `.cpp` into `bench/`.
2. Link it in `bench/CMakeLists.txt`.
3. Use the `da_bench::bench(label, iters, fn, bytes_per_op)` helper from `bench/bench_util.hpp`.

That's it — no macros, no registrar, no DSL.
