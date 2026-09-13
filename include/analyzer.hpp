#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
namespace da {
struct Evidence { std::string label; std::string detail; int weight; };
struct Detection { std::string category; std::string format; int confidence; std::vector<Evidence> evidence; };
struct Report {
  std::filesystem::path path;
  std::uintmax_t size{};
  std::string sha256;
  double entropy{};
  std::vector<Detection> detections;
  std::vector<std::string> notes;
};
Report analyze(const std::filesystem::path& path);
void print_report(const Report& r);
}
