cmake_minimum_required(VERSION 3.20)
project(digital_archaeologist VERSION 2.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# --- Library: the analysis engine, reusable from tests ---
add_library(da_core STATIC
  src/analyzer.cpp
  src/base64.cpp
  src/carve.cpp
  src/container.cpp
  src/crc32.cpp
  src/hashing.cpp
  src/strings_ex.cpp
  src/timeline.cpp
)
target_include_directories(da_core PUBLIC include)

# --- Executable: the CLI ---
add_executable(archaeologist src/main.cpp)
target_link_libraries(archaeologist PRIVATE da_core)

install(TARGETS archaeologist RUNTIME DESTINATION bin)

# --- Tests ---
include(CTest)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

# --- Fuzz targets (opt-in: requires clang -fsanitize=fuzzer) ---
option(DA_FUZZ "Build libFuzzer targets (needs clang)" OFF)
if(DA_FUZZ)
  add_subdirectory(fuzz)
endif()

# --- Benchmarks (opt-in; no third-party deps) ---
option(DA_BENCH "Build micro-benchmark executables" OFF)
if(DA_BENCH)
  add_subdirectory(bench)
endif()
