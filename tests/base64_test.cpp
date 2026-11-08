// Base64 round-trip tests.

#include <iostream>
#include <string>
#include <vector>

#include "base64.hpp"

static int fails = 0;

static void check(const std::vector<unsigned char>& in,
                  const std::string& encoded) {
  std::string got = da::base64_encode(in);
  if (got != encoded) {
    std::cerr << "FAIL encode: got " << got << " want " << encoded << "\n";
    ++fails;
  }
  auto back = da::base64_decode(encoded);
  if (back != in) {
    std::cerr << "FAIL decode roundtrip for " << encoded << "\n";
    ++fails;
  }
}

int main() {
  check({}, "");
  check({'f'}, "Zg==");
  check({'f', 'o'}, "Zm8=");
  check({'f', 'o', 'o'}, "Zm9v");
  check({'f', 'o', 'o', 'b'}, "Zm9vYg==");
  check({'f', 'o', 'o', 'b', 'a'}, "Zm9vYmE=");
  check({'f', 'o', 'o', 'b', 'a', 'r'}, "Zm9vYmFy");
  if (fails) return 1;
  std::cout << "base64 tests passed\n";
  return 0;
}
