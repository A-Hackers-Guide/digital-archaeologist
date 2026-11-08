// libFuzzer entrypoint for the analyzer.
//
// Feeds arbitrary bytes through `da::analyze_bytes` — the full signature
// detection, entropy, SHA-256 and JSON-formatting pipeline. A crash or
// sanitizer trap here is a bug; the fuzzer must stay silent indefinitely.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "analyzer.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  std::vector<unsigned char> buf(data, data + size);
  try {
    auto r = da::analyze_bytes("fuzz", buf);
    // Also exercise the JSON printer to catch escape/formatting bugs
    // against adversarial input. Output goes to /dev/null via the harness.
    da::print_report_json(r);
  } catch (...) {
    // analyze_bytes isn't supposed to throw on in-memory input, but catch
    // just in case so the fuzzer only flags actual crashes/UBSan hits.
  }
  return 0;
}
