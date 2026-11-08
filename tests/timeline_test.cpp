#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "timeline.hpp"

namespace fs = std::filesystem;

int main() {
  int fails = 0;
  auto dir = fs::temp_directory_path() / "da_timeline_test";
  fs::create_directories(dir);

  // GZIP header with a known mtime (2021-01-01 00:00:00 UTC = 1609459200)
  {
    std::vector<unsigned char> gz = {0x1f, 0x8b, 0x08, 0x00,
                                      0x00, 0x1c, 0xef, 0x5f,
                                      0x00, 0x03};
    auto p = dir / "a.gz";
    std::ofstream(p, std::ios::binary)
        .write(reinterpret_cast<const char*>(gz.data()),
               std::streamsize(gz.size()));
    auto t = da::extract_timeline(p, gz);
    bool found = std::any_of(t.begin(), t.end(), [](const auto& e) {
      return e.source == "gzip.mtime" && e.iso8601.rfind("2021-01-01", 0) == 0;
    });
    if (!found) {
      std::cerr << "FAIL: gzip mtime not recovered\n";
      ++fails;
    }
  }

  // ZIP local header with mtime and mdate fields set (2024-06-15 12:30:00)
  {
    std::vector<unsigned char> zip(30, 0);
    std::memcpy(zip.data(), "PK\x03\x04", 4);
    // dos time 12:30:00 → ((12<<11)|(30<<5)|(0/2)) = 0x63C0 (low byte first)
    zip[10] = 0xC0; zip[11] = 0x63;
    // dos date 2024-06-15 → (((2024-1980)<<9)|(6<<5)|15) = 0x58cf
    zip[12] = 0xcf; zip[13] = 0x58;
    auto p = dir / "a.zip";
    std::ofstream(p, std::ios::binary)
        .write(reinterpret_cast<const char*>(zip.data()),
               std::streamsize(zip.size()));
    auto t = da::extract_timeline(p, zip);
    bool found = std::any_of(t.begin(), t.end(), [](const auto& e) {
      return e.source == "zip.local.mtime" &&
             e.iso8601.rfind("2024-06-15T12:30", 0) == 0;
    });
    if (!found) {
      std::cerr << "FAIL: zip mtime not recovered\n";
      ++fails;
    }
  }

  if (fails) return 1;
  std::cout << "timeline tests passed\n";
  return 0;
}
