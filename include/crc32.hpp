#pragma once
#include <cstdint>
#include <vector>

namespace da {

// Streaming CRC-32 using the IEEE 802.3 / zlib polynomial (0xEDB88320
// reflected, equivalent to the PNG / ZIP CRC).
class Crc32 {
 public:
  Crc32();
  void update(const unsigned char* data, std::size_t len);
  std::uint32_t finalize();

 private:
  std::uint32_t state_;
};

std::uint32_t crc32_bytes(const std::vector<unsigned char>& data);

}  // namespace da
