#pragma once
#include <string>
#include <vector>
namespace da {
std::string base64_encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64_decode(const std::string& text);
}
