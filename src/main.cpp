// Digital Archaeologist CLI entry point.
//
// This is a thin dispatcher that parses arguments and hands the real work
// to the modules under include/*.hpp. The file is intentionally short and
// readable; please keep it that way.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "analyzer.hpp"
#include "base64.hpp"
#include "carve.hpp"
#include "container.hpp"
#include "crc32.hpp"
#include "hashing.hpp"
#include "strings_ex.hpp"
#include "timeline.hpp"

namespace fs = std::filesystem;

namespace {

constexpr const char* kVersion = "2.3.0";

void print_version() {
  std::cout << "Digital Archaeologist v" << kVersion << "\n";
}

void print_help(const std::string& topic = "") {
  if (topic == "unknown") {
    std::cout
        << "UNKNOWN-FORMAT RESEARCH MODE\n"
           "Runs every analysis pass (signatures, entropy, strings, partition\n"
           "evidence) and keeps going even when no signature matches. Use when\n"
           "you don't know what you're looking at and want everything on the\n"
           "table at once.\n"
           "\n"
           "  archaeologist --unknown[=windows|macos|linux] <file>\n";
    return;
  }
  if (topic == "password") {
    std::cout
        << "AUTHORIZED RECOVERY\n"
           "Digital Archaeologist is read-only. It inspects encryption or\n"
           "protection metadata and accepts user-supplied credentials where\n"
           "applicable. It does not bypass, crack, or attack protection\n"
           "schemes.\n";
    return;
  }
  if (topic == "features") {
    std::cout << "See docs/FEATURES.md for the full, numbered feature list.\n";
    return;
  }
  std::cout
      << "Digital Archaeologist v" << kVersion
      << " — forensic file archaeology\n\n"
         "Usage:\n"
         "  archaeologist [options] <file>\n"
         "\n"
         "Core:\n"
         "  --json                 Emit a single JSON object instead of text\n"
         "  --report FILE          Also write a plain-text report to FILE\n"
         "  --scan DIR             Recursively inventory files under DIR\n"
         "  --deep                 Run every analysis pass regardless of match\n"
         "  --unknown[=OS]         Alias of --deep with OS-specific hints\n"
         "  --quiet                Suppress informational output\n"
         "\n"
         "Analysis toggles (implied by --json/--report; off otherwise):\n"
         "  --stats                Dominant byte, printable ratio\n"
         "  --hash                 SHA-256 (always computed; prints it)\n"
         "  --crc32                Also compute the IEEE-802.3 CRC-32\n"
         "  --entropy              Shannon entropy class + value\n"
         "  --strings [N]          Printable strings of length >= N (default 4)\n"
         "  --ascii-only           With --strings: skip UTF-16LE scan\n"
         "  --utf16-only           With --strings: skip ASCII scan\n"
         "  --hex [N]              First N bytes as a canonical hexdump\n"
         "  --partitions           MBR/GPT partition-table evidence\n"
         "  --mime                 Print the best-guess MIME type and exit\n"
         "  --timeline             Filesystem + format-embedded timestamps\n"
         "  --carve OUTDIR         Carve embedded ZIP/GZIP/PNG/JPEG/PDF/...\n"
         "                         into OUTDIR as <offset>.<ext> files\n"
         "  --list                 List entries of a ZIP / TAR / GZIP\n"
         "                         (headers only; nothing is decompressed)\n"
         "\n"
         "Transport:\n"
         "  --base64-encode        Base64-encode the file to stdout\n"
         "  --base64-decode        Base64-decode stdin-or-file to stdout\n"
         "\n"
         "Search:\n"
         "  --find TEXT            Find ASCII substring; prints all offsets\n"
         "  --find-hex HEX         Find raw byte pattern; prints all offsets\n"
         "\n"
         "Safety:\n"
         "  --max-size BYTES       Cap in-memory structural analysis\n"
         "                         (default 2 GiB; SHA-256 always streams the\n"
         "                         whole file)\n"
         "\n"
         "Meta:\n"
         "  --version              Print version and exit\n"
         "  --help [topic]         Print help. Topics: unknown, password,\n"
         "                         features\n";
}

struct Args {
  std::string path;
  std::string scan_dir;
  std::string report_path;
  std::string find_text;
  std::string find_hex;
  std::string carve_dir;
  bool json = false;
  bool deep = false;
  bool stats = false;
  bool strings = false;
  bool ascii_only = false;
  bool utf16_only = false;
  bool hex = false;
  bool partitions = false;
  bool hash = false;
  bool crc32 = false;
  bool entropy = false;
  bool mime_only = false;
  bool timeline = false;
  bool list = false;
  bool base64_encode = false;
  bool base64_decode = false;
  bool quiet = false;
  std::size_t hex_count = 256;
  std::size_t strings_minlen = 4;
  std::uintmax_t max_bytes = std::uintmax_t(2) * 1024 * 1024 * 1024;
};

bool parse_size(const std::string& s, std::uintmax_t& out) {
  char* end = nullptr;
  std::uintmax_t v = std::strtoull(s.c_str(), &end, 10);
  if (!end || *end != 0) return false;
  out = v;
  return true;
}

std::optional<Args> parse_args(int argc, char** argv) {
  Args a;
  auto take_next = [&](int& i, const char* flag) -> const char* {
    if (i + 1 >= argc) {
      std::cerr << "error: " << flag << " requires an argument\n";
      return nullptr;
    }
    return argv[++i];
  };
  for (int i = 1; i < argc; ++i) {
    std::string x = argv[i];
    if (x == "--json") a.json = true;
    else if (x == "--deep") a.deep = true;
    else if (x.rfind("--unknown", 0) == 0) a.deep = true;
    else if (x == "--stats") a.stats = true;
    else if (x == "--strings") {
      a.strings = true;
      if (i + 1 < argc && std::isdigit((unsigned char)argv[i + 1][0]))
        a.strings_minlen = std::stoul(argv[++i]);
    }
    else if (x == "--hex") {
      a.hex = true;
      if (i + 1 < argc && std::isdigit((unsigned char)argv[i + 1][0]))
        a.hex_count = std::stoul(argv[++i]);
    }
    else if (x == "--partitions") a.partitions = true;
    else if (x == "--hash") a.hash = true;
    else if (x == "--crc32") a.crc32 = true;
    else if (x == "--entropy") a.entropy = true;
    else if (x == "--mime") a.mime_only = true;
    else if (x == "--timeline") a.timeline = true;
    else if (x == "--list") a.list = true;
    else if (x == "--ascii-only") a.ascii_only = true;
    else if (x == "--utf16-only") a.utf16_only = true;
    else if (x == "--carve") {
      auto v = take_next(i, "--carve");
      if (!v) return std::nullopt;
      a.carve_dir = v;
    }
    else if (x == "--report") {
      auto v = take_next(i, "--report");
      if (!v) return std::nullopt;
      a.report_path = v;
    }
    else if (x == "--find") {
      auto v = take_next(i, "--find");
      if (!v) return std::nullopt;
      a.find_text = v;
    }
    else if (x == "--find-hex") {
      auto v = take_next(i, "--find-hex");
      if (!v) return std::nullopt;
      a.find_hex = v;
    }
    else if (x == "--base64-encode") a.base64_encode = true;
    else if (x == "--base64-decode") a.base64_decode = true;
    else if (x == "--scan") {
      auto v = take_next(i, "--scan");
      if (!v) return std::nullopt;
      a.scan_dir = v;
    }
    else if (x == "--quiet") a.quiet = true;
    else if (x == "--max-size") {
      auto v = take_next(i, "--max-size");
      if (!v) return std::nullopt;
      if (!parse_size(v, a.max_bytes)) {
        std::cerr << "error: --max-size takes a decimal byte count\n";
        return std::nullopt;
      }
    }
    else if (x == "--version") { print_version(); std::exit(0); }
    else if (x == "--help" || x == "-h") {
      print_help(i + 1 < argc ? argv[i + 1] : "");
      std::exit(0);
    }
    else if (!x.empty() && x[0] == '-') {
      // Unknown flag — warn but keep going; back-compat with the older build.
      std::cerr << "warning: unknown flag ignored: " << x << "\n";
    }
    else {
      a.path = x;
    }
  }
  return a;
}

std::vector<unsigned char> read_file_all(const std::string& p,
                                         std::uintmax_t cap) {
  std::ifstream f(p, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open input: " + p);
  f.seekg(0, std::ios::end);
  auto sz = f.tellg();
  f.seekg(0);
  if (sz < 0) throw std::runtime_error("cannot stat input: " + p);
  std::uintmax_t n = static_cast<std::uintmax_t>(sz);
  if (n > cap) n = cap;
  std::vector<unsigned char> d(static_cast<std::size_t>(n));
  if (n) f.read(reinterpret_cast<char*>(d.data()),
                static_cast<std::streamsize>(n));
  return d;
}

void hexdump(const std::vector<unsigned char>& d, std::size_t n) {
  std::size_t limit = std::min(n, d.size());
  std::ios_base::fmtflags saved = std::cout.flags();
  for (std::size_t i = 0; i < limit; i += 16) {
    std::cout << std::hex << std::setw(8) << std::setfill('0') << i << "  ";
    for (std::size_t j = 0; j < 16; ++j) {
      if (i + j < limit) {
        std::cout << std::setw(2) << std::setfill('0')
                  << int(d[i + j]) << ' ';
      } else {
        std::cout << "   ";
      }
    }
    std::cout << " |";
    for (std::size_t j = 0; j < 16 && i + j < limit; ++j) {
      char c = char(d[i + j]);
      std::cout << ((c >= 32 && c < 127) ? c : '.');
    }
    std::cout << "|\n";
  }
  std::cout.flags(saved);
}

std::vector<std::size_t> find_substring(const std::vector<unsigned char>& d,
                                        const std::string& needle) {
  std::vector<std::size_t> hits;
  if (needle.empty() || d.size() < needle.size()) return hits;
  const unsigned char* begin = d.data();
  const unsigned char* end = d.data() + d.size();
  const unsigned char* n = reinterpret_cast<const unsigned char*>(needle.data());
  std::size_t nlen = needle.size();
  const unsigned char* p = begin;
  while (true) {
    auto it = std::search(p, end, n, n + nlen);
    if (it == end) break;
    hits.push_back(std::size_t(it - begin));
    p = it + 1;
  }
  return hits;
}

std::vector<unsigned char> hex_to_bytes(const std::string& s) {
  std::string clean;
  clean.reserve(s.size());
  for (char c : s) if (!std::isspace((unsigned char)c)) clean += c;
  if (clean.size() % 2) throw std::runtime_error("odd-length hex pattern");
  std::vector<unsigned char> out;
  out.reserve(clean.size() / 2);
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < clean.size(); i += 2) {
    int hi = nib(clean[i]), lo = nib(clean[i + 1]);
    if (hi < 0 || lo < 0) throw std::runtime_error("non-hex digit in pattern");
    out.push_back((unsigned char)((hi << 4) | lo));
  }
  return out;
}

void emit_strings(const std::vector<unsigned char>& d, std::size_t minlen,
                  bool ascii, bool utf16le) {
  auto s = da::extract_strings(d, minlen, ascii, utf16le);
  for (const auto& f : s) {
    std::cout << f.encoding << "@0x" << std::hex << f.offset << std::dec
              << ": " << f.text << "\n";
  }
}

int do_carve(const Args& a) {
  auto d = read_file_all(a.path, a.max_bytes);
  auto carved = da::carve(d, a.carve_dir);
  for (const auto& c : carved) {
    std::cout << "carved " << c.format << " @0x" << std::hex << c.offset
              << std::dec << " len=" << c.length << " -> " << c.out.string()
              << "\n";
  }
  if (!a.quiet)
    std::cout << carved.size() << " piece(s) written to " << a.carve_dir
              << "\n";
  return 0;
}

int do_timeline(const Args& a) {
  auto d = read_file_all(a.path, a.max_bytes);
  auto events = da::extract_timeline(a.path, d);
  for (const auto& e : events) {
    std::cout << e.source << "\t" << e.iso8601 << "\n";
  }
  return 0;
}

int do_list(const Args& a) {
  auto d = read_file_all(a.path, a.max_bytes);
  auto l = da::list_container(d);
  if (l.format.empty()) {
    std::cerr << "not a supported container\n";
    return 1;
  }
  std::cout << l.format;
  if (!l.inner_name.empty()) std::cout << "  inner_name=" << l.inner_name;
  std::cout << "  entries=" << l.entries.size()
            << (l.truncated ? "  (truncated)" : "") << "\n";
  for (const auto& e : l.entries) {
    std::cout << e.size << "\t" << e.path;
    if (e.crc32) {
      char buf[12];
      std::snprintf(buf, sizeof(buf), "%08x", e.crc32);
      std::cout << "\t" << buf;
    }
    std::cout << "\n";
  }
  return 0;
}

int do_scan(const Args& a) {
  std::error_code ec;
  for (fs::recursive_directory_iterator it(a.scan_dir, ec), end; it != end;
       it.increment(ec)) {
    if (ec) {
      std::cerr << "scan: " << ec.message() << "\n";
      ec.clear();
      continue;
    }
    if (!it->is_regular_file(ec) || ec) { ec.clear(); continue; }
    try {
      auto r = da::analyze(it->path(), {a.max_bytes});
      std::cout << it->path().string() << "\t"
                << (r.detections.empty() ? std::string("unknown")
                                         : r.detections.front().format)
                << "\t" << r.size << "\t" << r.sha256 << "\n";
    } catch (const std::exception& e) {
      std::cerr << "scan: " << it->path().string() << ": " << e.what() << "\n";
    }
  }
  return 0;
}

int do_mime(const Args& a) {
  auto r = da::analyze(a.path, {a.max_bytes});
  std::cout << (r.detections.empty() || r.detections.front().mime.empty()
                    ? std::string("application/octet-stream")
                    : r.detections.front().mime)
            << "\n";
  return 0;
}

int do_find(const Args& a) {
  auto d = read_file_all(a.path, a.max_bytes);
  std::vector<std::size_t> hits;
  if (!a.find_text.empty()) {
    hits = find_substring(d, a.find_text);
  } else {
    auto bytes = hex_to_bytes(a.find_hex);
    hits = find_substring(d, std::string(bytes.begin(), bytes.end()));
  }
  if (hits.empty()) { std::cout << "NOT FOUND\n"; return 1; }
  for (auto h : hits)
    std::cout << "FOUND at offset " << h << " (0x" << std::hex << h << std::dec
              << ")\n";
  return 0;
}

int do_analyze(const Args& a) {
  auto r = da::analyze(a.path, {a.max_bytes});
  if (a.json) {
    da::print_report_json(r);
  } else {
    da::print_report(r);
    if (a.crc32) {
      auto d = read_file_all(a.path, a.max_bytes);
      char buf[12];
      std::snprintf(buf, sizeof(buf), "%08x", da::crc32_bytes(d));
      std::cout << "crc32: " << buf << "\n";
    }
    if (a.stats) {
      std::cout << "dominant_byte: 0x" << std::hex << r.dominant_byte
                << std::dec << " count=" << r.dominant_byte_count << "\n";
    }
    if (a.timeline) {
      auto d = read_file_all(a.path, a.max_bytes);
      std::cout << "--- timeline ---\n";
      for (const auto& e : da::extract_timeline(a.path, d))
        std::cout << e.source << "\t" << e.iso8601 << "\n";
    }
    if (a.hex || a.strings) {
      auto d = read_file_all(a.path, a.max_bytes);
      if (a.strings) {
        std::cout << "--- strings (min " << a.strings_minlen << ") ---\n";
        bool ascii = !a.utf16_only;
        bool utf = !a.ascii_only;
        emit_strings(d, a.strings_minlen, ascii, utf);
      }
      if (a.hex) {
        std::cout << "--- hex (first " << a.hex_count << " bytes) ---\n";
        hexdump(d, a.hex_count);
      }
    }
  }
  if (!a.report_path.empty()) {
    std::ofstream o(a.report_path);
    o << "Digital Archaeologist report v" << kVersion << "\n"
      << "file=" << a.path << "\n"
      << "size=" << r.size << "\n"
      << "sha256=" << r.sha256 << "\n"
      << "entropy=" << r.entropy << "\n"
      << "detections=" << r.detections.size() << "\n";
    for (const auto& det : r.detections) {
      o << "detection\t" << det.category << "\t" << det.format << "\t"
        << det.confidence << "\t" << det.mime << "\n";
    }
    if (!a.quiet) std::cout << "report written: " << a.report_path << "\n";
  }
  return 0;
}

int do_base64(const Args& a) {
  if (a.base64_encode) {
    auto d = read_file_all(a.path, a.max_bytes);
    std::cout << da::base64_encode(d) << "\n";
    return 0;
  }
  // decode
  std::ifstream f(a.path, std::ios::binary);
  if (!f) { std::cerr << "cannot open " << a.path << "\n"; return 1; }
  std::string text((std::istreambuf_iterator<char>(f)),
                   std::istreambuf_iterator<char>());
  auto bytes = da::base64_decode(text);
  std::cout.write(reinterpret_cast<const char*>(bytes.data()),
                  std::streamsize(bytes.size()));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) { print_help(); return 2; }
  auto maybe = parse_args(argc, argv);
  if (!maybe) return 2;
  Args a = *maybe;
  try {
    if (!a.scan_dir.empty()) return do_scan(a);
    if (a.path.empty()) { print_help(); return 2; }
    if (!a.carve_dir.empty()) return do_carve(a);
    if (a.list) return do_list(a);
    if (a.base64_encode || a.base64_decode) return do_base64(a);
    if (!a.find_text.empty() || !a.find_hex.empty()) return do_find(a);
    if (a.mime_only) return do_mime(a);
    if (a.timeline && !a.json && !a.crc32 && !a.stats && !a.hex && !a.strings) {
      return do_timeline(a);
    }
    return do_analyze(a);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
