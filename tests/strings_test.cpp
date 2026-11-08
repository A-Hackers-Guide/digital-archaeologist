#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "strings_ex.hpp"

int main() {
  int fails = 0;

  // ASCII + separator + another ASCII + UTF-16LE "Hello".
  std::vector<unsigned char> d;
  const char* a1 = "hello world";
  d.insert(d.end(), a1, a1 + std::strlen(a1));
  d.push_back(0);
  const char* a2 = "foobar";
  d.insert(d.end(), a2, a2 + std::strlen(a2));
  d.push_back(0);
  const char* u = "Hello UTF16";
  for (const char* p = u; *p; ++p) {
    d.push_back((unsigned char)*p);
    d.push_back(0);
  }

  auto s = da::extract_strings(d, 4, true, true);
  auto has_text = [&](const std::string& needle, const std::string& enc) {
    return std::any_of(s.begin(), s.end(), [&](const da::FoundString& f) {
      return f.encoding == enc && f.text.find(needle) != std::string::npos;
    });
  };

  if (!has_text("hello world", "ascii")) { std::cerr << "FAIL ascii1\n"; ++fails; }
  if (!has_text("foobar", "ascii")) { std::cerr << "FAIL ascii2\n"; ++fails; }
  // The UTF-16 scan may greedily pick up the trailing ASCII char whose next
  // byte is the ASCII terminator NUL; that is correct behavior for a strings
  // extractor, so we check that "Hello UTF16" appears as a substring rather
  // than requiring an exact match.
  if (!has_text("Hello UTF16", "utf-16le")) {
    std::cerr << "FAIL utf16\n";
    ++fails;
  }

  if (fails) return 1;
  std::cout << "strings tests passed\n";
  return 0;
}
