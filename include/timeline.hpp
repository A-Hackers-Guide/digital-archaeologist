#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace da {

struct TimelineEvent {
  std::string source;    // "fs.mtime", "zip.local.mtime", "pe.timedatestamp"
  std::string iso8601;   // "2026-11-08T13:42:11Z" or "~2026-11-08" for coarse
};

// Filesystem mtime + format-embedded timestamps where available.
std::vector<TimelineEvent> extract_timeline(
    const std::filesystem::path& path,
    const std::vector<unsigned char>& data);

}  // namespace da
