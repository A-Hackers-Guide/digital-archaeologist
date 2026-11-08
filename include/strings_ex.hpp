#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace da {

struct FoundString {
  std::size_t offset = 0;
  std::string encoding;  // "ascii" or "utf-16le"
  std::string text;
};

// Collect printable strings of length >= minlen. Scans for ASCII and
// UTF-16LE in one pass; either can be disabled.
std::vector<FoundString> extract_strings(const std::vector<unsigned char>& data,
                                         std::size_t minlen = 4,
                                         bool ascii = true,
                                         bool utf16le = true);

}  // namespace da
