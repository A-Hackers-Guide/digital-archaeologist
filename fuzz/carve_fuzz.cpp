// libFuzzer entrypoint for the signature carver.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

#include "carve.hpp"

static const std::filesystem::path kOut =
    std::filesystem::temp_directory_path() / "da_fuzz_carve_out";

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  std::error_code ec;
  std::filesystem::create_directories(kOut, ec);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  std::vector<unsigned char> buf(data, data + size);
  try {
    (void)da::carve(buf, kOut);
  } catch (...) {
  }
  return 0;
}
