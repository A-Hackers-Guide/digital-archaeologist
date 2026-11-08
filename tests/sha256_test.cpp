// SHA-256 streaming vs batched correctness, plus the NIST empty-string vector
// and the classic "abc" vector.

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "hashing.hpp"

int main() {
  int fails = 0;

  // Empty input
  {
    std::vector<unsigned char> empty;
    std::string got = da::sha256_bytes(empty);
    const std::string want =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if (got != want) {
      std::cerr << "FAIL: empty sha256 = " << got << "\n";
      ++fails;
    }
  }

  // "abc"
  {
    std::string abc = "abc";
    std::vector<unsigned char> v(abc.begin(), abc.end());
    std::string got = da::sha256_bytes(v);
    const std::string want =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (got != want) {
      std::cerr << "FAIL: 'abc' sha256 = " << got << "\n";
      ++fails;
    }
  }

  // A 1 MiB block of zeros via streaming vs batched should agree.
  {
    std::vector<unsigned char> block(1024 * 1024, 0);
    std::string batched = da::sha256_bytes(block);

    da::Sha256 h;
    // feed in 7 KiB chunks so the inner buffer wraps mid-block
    std::size_t off = 0, step = 7 * 1024;
    while (off < block.size()) {
      std::size_t take = std::min(step, block.size() - off);
      h.update(block.data() + off, take);
      off += take;
    }
    std::string streamed = h.finalize();
    if (batched != streamed) {
      std::cerr << "FAIL: streamed/batched mismatch (" << batched << " vs "
                << streamed << ")\n";
      ++fails;
    }
  }

  // Longer multi-block message: 1_000_000 'a' is a SHA-256 known vector.
  {
    std::vector<unsigned char> a(1000000, 'a');
    std::string got = da::sha256_bytes(a);
    const std::string want =
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    if (got != want) {
      std::cerr << "FAIL: 1M 'a' sha256 = " << got << "\n";
      ++fails;
    }
  }

  if (fails) return 1;
  std::cout << "sha256 tests passed\n";
  return 0;
}
