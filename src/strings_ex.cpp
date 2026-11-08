#include "strings_ex.hpp"

namespace da {
namespace {

inline bool is_print(unsigned char c) {
  return c == '\t' || (c >= 32 && c < 127);
}

}  // namespace

std::vector<FoundString> extract_strings(const std::vector<unsigned char>& d,
                                         std::size_t minlen, bool ascii,
                                         bool utf16le) {
  std::vector<FoundString> out;

  if (ascii) {
    std::size_t start = 0;
    std::string cur;
    for (std::size_t i = 0; i < d.size(); ++i) {
      if (is_print(d[i])) {
        if (cur.empty()) start = i;
        cur.push_back(char(d[i]));
      } else {
        if (cur.size() >= minlen)
          out.push_back({start, "ascii", std::move(cur)});
        cur.clear();
      }
    }
    if (cur.size() >= minlen)
      out.push_back({start, "ascii", std::move(cur)});
  }

  if (utf16le) {
    // Two scans offset by 0 and 1 catch 16-bit-aligned and misaligned runs.
    for (std::size_t base : {std::size_t(0), std::size_t(1)}) {
      std::size_t start = 0;
      std::string cur;
      for (std::size_t i = base; i + 1 < d.size(); i += 2) {
        unsigned char lo = d[i];
        unsigned char hi = d[i + 1];
        if (hi == 0 && is_print(lo)) {
          if (cur.empty()) start = i;
          cur.push_back(char(lo));
        } else {
          if (cur.size() >= minlen)
            out.push_back({start, "utf-16le", std::move(cur)});
          cur.clear();
        }
      }
      if (cur.size() >= minlen)
        out.push_back({start, "utf-16le", std::move(cur)});
    }
  }

  return out;
}

}  // namespace da
