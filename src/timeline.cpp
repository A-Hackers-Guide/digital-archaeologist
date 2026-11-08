#include "timeline.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>
#include <string>

namespace da {
namespace {

std::string fmt_iso(std::time_t t) {
  std::tm tm{};
#ifdef _WIN32
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec);
  return buf;
}

std::string dos_time(std::uint16_t date, std::uint16_t time) {
  int year = ((date >> 9) & 0x7f) + 1980;
  int mon  = (date >> 5) & 0x0f;
  int day  = date & 0x1f;
  int hour = (time >> 11) & 0x1f;
  int min  = (time >> 5) & 0x3f;
  int sec  = (time & 0x1f) * 2;
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                year, mon, day, hour, min, sec);
  return buf;
}

inline std::uint16_t u16le(const std::vector<unsigned char>& d, std::size_t o) {
  return std::uint16_t(d[o]) | (std::uint16_t(d[o + 1]) << 8);
}
inline std::uint32_t u32le(const std::vector<unsigned char>& d, std::size_t o) {
  return std::uint32_t(d[o]) | (std::uint32_t(d[o + 1]) << 8) |
         (std::uint32_t(d[o + 2]) << 16) | (std::uint32_t(d[o + 3]) << 24);
}

bool matches(const std::vector<unsigned char>& d,
             std::initializer_list<unsigned char> s, std::size_t off = 0) {
  if (off + s.size() > d.size()) return false;
  return std::equal(s.begin(), s.end(), d.begin() + off);
}

void zip_local_mtime(const std::vector<unsigned char>& d,
                     std::vector<TimelineEvent>& out) {
  if (d.size() < 30) return;
  if (!matches(d, {'P', 'K', 0x03, 0x04})) return;
  std::uint16_t time = u16le(d, 10);
  std::uint16_t date = u16le(d, 12);
  out.push_back({"zip.local.mtime", dos_time(date, time)});
}

void pe_timedatestamp(const std::vector<unsigned char>& d,
                      std::vector<TimelineEvent>& out) {
  if (d.size() < 0x40 || d[0] != 'M' || d[1] != 'Z') return;
  std::uint32_t pe_off = u32le(d, 0x3c);
  if (pe_off + 8 >= d.size()) return;
  if (!matches(d, {'P', 'E', 0, 0}, pe_off)) return;
  // COFF header starts at pe_off+4. TimeDateStamp is at COFF+4 → pe_off+8.
  std::uint32_t ts = u32le(d, pe_off + 8);
  if (ts == 0 || ts > 2'000'000'000u /* far future */) return;
  out.push_back({"pe.timedatestamp", fmt_iso(std::time_t(ts))});
}

void gzip_mtime(const std::vector<unsigned char>& d,
                std::vector<TimelineEvent>& out) {
  if (d.size() < 10 || d[0] != 0x1f || d[1] != 0x8b) return;
  std::uint32_t ts = u32le(d, 4);
  if (ts == 0) return;
  out.push_back({"gzip.mtime", fmt_iso(std::time_t(ts))});
}

// Scan the first ~16 KiB of a PDF for /CreationDate and /ModDate.
void pdf_dates(const std::vector<unsigned char>& d,
               std::vector<TimelineEvent>& out) {
  if (d.size() < 5 || !matches(d, {'%', 'P', 'D', 'F', '-'})) return;
  std::string head(d.begin(),
                   d.begin() + std::min<std::size_t>(d.size(), 16 * 1024));
  for (const char* key : {"/CreationDate", "/ModDate"}) {
    std::size_t p = head.find(key);
    if (p == std::string::npos) continue;
    std::size_t l = head.find('(', p);
    std::size_t r = (l == std::string::npos) ? std::string::npos
                                              : head.find(')', l);
    if (l == std::string::npos || r == std::string::npos) continue;
    std::string raw = head.substr(l + 1, r - l - 1);
    // Typical form: D:20261108134211Z
    if (raw.size() >= 16 && raw.substr(0, 2) == "D:") {
      char buf[32];
      std::snprintf(buf, sizeof(buf),
                    "%4.4s-%2.2s-%2.2sT%2.2s:%2.2s:%2.2sZ",
                    raw.c_str() + 2, raw.c_str() + 6, raw.c_str() + 8,
                    raw.c_str() + 10, raw.c_str() + 12, raw.c_str() + 14);
      out.push_back({std::string("pdf.") + (key + 1), buf});
    }
  }
}

}  // namespace

std::vector<TimelineEvent> extract_timeline(
    const std::filesystem::path& path,
    const std::vector<unsigned char>& data) {
  std::vector<TimelineEvent> out;
  std::error_code ec;
  auto ft = std::filesystem::last_write_time(path, ec);
  if (!ec) {
    // Convert to time_t via system_clock best-effort (lossy on some platforms
    // but good enough for a forensic read).
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ft - std::filesystem::file_time_type::clock::now() +
        std::chrono::system_clock::now());
    std::time_t t = std::chrono::system_clock::to_time_t(sctp);
    out.push_back({"fs.mtime", fmt_iso(t)});
  }

  zip_local_mtime(data, out);
  pe_timedatestamp(data, out);
  gzip_mtime(data, out);
  pdf_dates(data, out);

  return out;
}

}  // namespace da
