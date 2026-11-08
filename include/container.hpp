#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace da {

// Container-walk metadata: file names and sizes without decompression.
// Nothing here uncompresses, inflates, or interprets payload bytes;
// we only read the headers / indexes that are stored in plaintext.

struct ContainerEntry {
  std::string path;        // file name as the archive stores it
  std::uint64_t size = 0;  // uncompressed size where known, else 0
  std::uint64_t offset = 0; // byte offset of the entry's payload in the archive
  std::uint32_t crc32 = 0;  // where the format stores one; else 0
  std::uint64_t mtime = 0;  // unix seconds where known, else 0
};

struct ContainerListing {
  std::string format;                     // "ZIP" / "TAR" / "GZIP"
  std::vector<ContainerEntry> entries;    // entry metadata
  std::string inner_name;                 // GZIP member filename (FNAME flag)
  bool truncated = false;                 // listing cut off (bad / huge archive)
};

// List the contents of a container by reading only its index/header.
// Returns an empty listing (format left blank) if the buffer isn't one of
// the supported containers or the index can't be parsed.
ContainerListing list_container(const std::vector<unsigned char>& data);

}  // namespace da
