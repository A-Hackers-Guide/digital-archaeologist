#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace da {

// Streaming SHA-256 so we can hash files larger than RAM without
// buffering the whole thing. Call update() repeatedly, then finalize()
// to get the 64-char lowercase hex digest.
class Sha256 {
 public:
  Sha256();
  void update(const unsigned char* data, std::size_t len);
  std::string finalize();

 private:
  std::array<std::uint32_t, 8> h_{};
  std::array<unsigned char, 64> buf_{};
  std::uint64_t bits_ = 0;
  std::size_t buf_len_ = 0;
  void transform(const unsigned char* block);
};

// Convenience: hash a whole in-memory buffer.
std::string sha256_bytes(const std::vector<unsigned char>& data);

// Convenience: hash a file by streaming it, chunk by chunk.
// Throws std::runtime_error if the file can't be opened.
std::string sha256_file(const std::filesystem::path& path);

}  // namespace da
