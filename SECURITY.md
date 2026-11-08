# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

- **Preferred:** GitHub's [private security advisory](https://github.com/A-Hackers-Guide/digital-archaeologist/security/advisories/new) workflow.
- **Email fallback:** open a draft PR titled `SECURITY` with contact details and we'll move it off the public surface.

Expect an acknowledgement within 72 hours and, where there's an actual issue to fix, a patched release within 14 days.

## Threat model

Digital Archaeologist is a **read-only** analyser. It opens files you point it at and produces reports. Specifically:

- It **reads** the input file (always) and reads under `--scan DIR` (recursive).
- It **writes** only to paths you supply: `--report FILE`, `--carve OUTDIR`, or `--base64-decode` stdout redirect.
- It does **not** connect to the network.
- It does **not** execute code from the input.
- It does **not** load third-party libraries at runtime.

That means:

- **In scope** — anything that lets a crafted input escape those boundaries: a buffer-over-read in the analyser, a path-traversal in `--carve`, a signed-integer overflow that panics the binary, a hostile container that DoSes the walker past the 10 000-entry cap, a format whose detection confuses another format.
- **In scope** — integer-overflow / use-after-free / out-of-bounds read reachable from the public `da::analyze_bytes` / `da::list_container` / `da::carve` entry points.
- **Out of scope** — the fact that you can `--carve` into a directory that then overwrites existing files. We only write files named `<hex-offset>.<ext>`, and `--carve` requires an explicit output directory.

## CI quality gates

Every PR runs:

- 3-OS build matrix (Linux / macOS / Windows)
- CTest suite (SHA-256 vectors, base64 RFC 4648, CRC-32 vectors, 70+ fixture-asserted detections, container walk, strings / carve / timeline)
- ASan + UBSan on Linux
- libFuzzer on `da::analyze_bytes` and `da::carve` for 60 seconds each under ASan + UBSan
- CodeRabbit review

See [`.github/workflows/sanitize.yml`](.github/workflows/sanitize.yml) and [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Dependencies

Zero third-party runtime dependencies. Everything is standard C++17. The only external moving part is the GitHub Actions CI stack.

## Credit

We credit reporters in `CHANGELOG.md` once a fix ships, unless you ask us not to.
