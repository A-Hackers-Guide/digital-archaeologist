#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <vector>

#include "carve.hpp"

namespace fs = std::filesystem;

int main() {
  int fails = 0;
  // One PNG header, then a JPEG header, then a ZIP local-file header.
  std::vector<unsigned char> d;
  const std::vector<unsigned char> png = {0x89, 'P', 'N', 'G', 0x0d,
                                           0x0a, 0x1a, 0x0a, 0, 0, 0, 13};
  const std::vector<unsigned char> jpg = {0xff, 0xd8, 0xff, 0xe0,
                                           0, 16, 'J', 'F', 'I', 'F', 0};
  const std::vector<unsigned char> zip = {'P', 'K', 0x03, 0x04, 0x14, 0, 0};
  d.insert(d.end(), png.begin(), png.end());
  for (int i = 0; i < 16; ++i) d.push_back(0);
  d.insert(d.end(), jpg.begin(), jpg.end());
  for (int i = 0; i < 16; ++i) d.push_back(0);
  d.insert(d.end(), zip.begin(), zip.end());

  auto out = fs::temp_directory_path() / "da_carve_test";
  fs::remove_all(out);
  auto carved = da::carve(d, out);

  if (carved.size() != 3) {
    std::cerr << "FAIL: expected 3 carved pieces, got " << carved.size() << "\n";
    ++fails;
  } else {
    if (carved[0].format != "PNG") { std::cerr << "FAIL: [0] not PNG\n"; ++fails; }
    if (carved[1].format != "JPEG") { std::cerr << "FAIL: [1] not JPEG\n"; ++fails; }
    if (carved[2].format != "ZIP") { std::cerr << "FAIL: [2] not ZIP\n"; ++fails; }
    for (const auto& c : carved) {
      if (!fs::exists(c.out)) {
        std::cerr << "FAIL: output file missing: " << c.out << "\n";
        ++fails;
      }
    }
  }

  if (fails) return 1;
  std::cout << "carve tests passed\n";
  return 0;
}
