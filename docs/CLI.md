# CLI reference

```text
archaeologist [options] <file>
```

## Core

| Flag | Effect |
|---|---|
| `--json` | Emit a single JSON object instead of the text report |
| `--report FILE` | Also write a plain-text report to FILE |
| `--scan DIR` | Recursively inventory every regular file under DIR (path, format, size, sha256) |
| `--deep` | Run every analysis pass regardless of whether a signature already matched |
| `--unknown[=OS]` | Alias of `--deep` with OS-specific hint phrasing (`windows`, `macos`, `linux`) |
| `--quiet` | Suppress informational output |

## Analysis toggles

| Flag | Effect |
|---|---|
| `--stats` | Dominant byte, printable ratio |
| `--hash` | SHA-256 (always computed; this just prints it) |
| `--crc32` | Also compute the IEEE-802.3 CRC-32 |
| `--entropy` | Shannon entropy classification + value |
| `--strings [N]` | Printable strings (ASCII + UTF-16LE) of length ≥ N. Default N = 4. Output: `<encoding>@<offset>: <text>` |
| `--ascii-only` | With `--strings`, skip the UTF-16LE scan |
| `--utf16-only` | With `--strings`, skip the ASCII scan |
| `--hex [N]` | First N bytes as a canonical hexdump. Default N = 256 |
| `--partitions` | MBR/GPT partition-table evidence |
| `--mime` | Print the best-guess MIME type and exit |
| `--timeline` | Filesystem mtime + format-embedded timestamps |

## Investigation

| Flag | Effect |
|---|---|
| `--find TEXT` | Find an ASCII substring; prints **every** match offset (decimal + hex) |
| `--find-hex HEX` | Find a raw byte pattern; prints every match offset |
| `--carve OUTDIR` | Carve embedded files into OUTDIR as `<offset>.<ext>`. Covers ZIP, GZIP, PNG, JPEG, PDF, ELF, MZ/PE, 7z, RAR, BZIP2, XZ, Ogg, Matroska, SQLite |

## Transport

| Flag | Effect |
|---|---|
| `--base64-encode` | Base64-encode the file to stdout |
| `--base64-decode` | Base64-decode the file to stdout |

## Safety

| Flag | Effect |
|---|---|
| `--max-size BYTES` | Cap in-memory structural analysis. Default 2 GiB. SHA-256 still streams the whole file. |

## Meta

| Flag | Effect |
|---|---|
| `--version` | Print version and exit |
| `--help [topic]` | Print help. Topics: `unknown`, `password`, `features` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis completed; detection(s) reported (may be empty) |
| 1 | Runtime error (couldn't open input, I/O failure, bad `--max-size`, etc.) |
| 2 | Usage error (no arguments, missing argument to a flag) |

For `--find` and `--find-hex`, the exit code is 1 when the pattern is not present.
