#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace da {

struct Carved {
  std::size_t offset = 0;
  std::size_t length = 0;
  std::string format;        // "ZIP", "GZIP", "PNG", "JPEG", "PDF", "ELF"
  std::filesystem::path out;  // where it was written
};

// Scan `data` for embedded file signatures and write each run to `out_dir`.
// Returns a list describing what was carved and where it ended up.
//
// This is deliberately conservative: the start of each signature is a
// recognised magic number; the length is a best-guess that trails to the
// next matching signature or EOF. Nothing is uncompressed or interpreted.
std::vector<Carved> carve(const std::vector<unsigned char>& data,
                          const std::filesystem::path& out_dir);

}  // namespace da
