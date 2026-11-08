#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace da {

// One piece of evidence contributing to a Detection's confidence.
struct Evidence {
  std::string label;    // e.g. "signature", "structure", "offset"
  std::string detail;   // human-readable description
  int weight = 0;       // 0..100 contribution toward the Detection's score
};

struct Detection {
  std::string category;                  // "executable", "image", "filesystem", ...
  std::string format;                    // "PNG", "ELF", "ext2/ext3/ext4", ...
  int confidence = 0;                    // 0..100
  std::string mime;                      // "image/png", or "" if no stable MIME
  std::vector<Evidence> evidence;
};

struct Report {
  std::filesystem::path path;
  std::uintmax_t size = 0;
  std::string sha256;                    // 64 hex chars
  double entropy = 0;                    // 0..8
  double printable_ratio = 0;            // 0..1
  unsigned dominant_byte = 0;
  std::uint64_t dominant_byte_count = 0;
  std::vector<Detection> detections;     // most-specific first
  std::vector<std::string> notes;
  bool truncated = false;                // true if file exceeded --max-size
  std::uintmax_t bytes_scanned = 0;      // how many bytes analysis actually looked at
};

struct AnalyzeOptions {
  // Maximum bytes to load into memory for structural analysis.
  // SHA-256 always streams the full file regardless of this cap.
  std::uintmax_t max_bytes = std::uintmax_t(2) * 1024 * 1024 * 1024;  // 2 GiB
};

Report analyze(const std::filesystem::path& path, AnalyzeOptions opt = {});

// Same as analyze(), but reads from an in-memory buffer. Useful for fuzzing
// and unit tests. `synthetic_name` is reported in Report::path.
Report analyze_bytes(const std::string& synthetic_name,
                     const std::vector<unsigned char>& data,
                     AnalyzeOptions opt = {});

// Pretty-print a Report to stdout in human form. JSON is a separate call.
void print_report(const Report& r);

// Print a Report as a single JSON object (stable field names).
void print_report_json(const Report& r);

}  // namespace da
