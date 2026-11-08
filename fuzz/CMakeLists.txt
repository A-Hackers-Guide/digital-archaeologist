add_executable(da_fuzz_analyze analyze_fuzz.cpp)
target_link_libraries(da_fuzz_analyze PRIVATE da_core)
target_compile_options(da_fuzz_analyze PRIVATE -fsanitize=fuzzer)
target_link_options(da_fuzz_analyze PRIVATE -fsanitize=fuzzer)

add_executable(da_fuzz_carve carve_fuzz.cpp)
target_link_libraries(da_fuzz_carve PRIVATE da_core)
target_compile_options(da_fuzz_carve PRIVATE -fsanitize=fuzzer)
target_link_options(da_fuzz_carve PRIVATE -fsanitize=fuzzer)
