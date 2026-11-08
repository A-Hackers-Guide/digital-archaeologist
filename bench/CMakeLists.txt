add_executable(da_bench_analyze analyze_bench.cpp)
target_link_libraries(da_bench_analyze PRIVATE da_core)

add_executable(da_bench_sha256 sha256_bench.cpp)
target_link_libraries(da_bench_sha256 PRIVATE da_core)

add_executable(da_bench_carve carve_bench.cpp)
target_link_libraries(da_bench_carve PRIVATE da_core)
