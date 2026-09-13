# CLI reference

`archaeologist <file>` is the default extension-independent analyzer.

Profiles:
- `--unknown` / `-u`: conservative unknown-format investigation.
- `--linux` / `-L`: Linux-oriented interpretation.
- `--macos` / `-M`: macOS-oriented interpretation.
- `--windows` / `-W`: Windows-oriented interpretation.
- `--password` / `-p`: encryption/recovery metadata only.

Transport:
- `--transport-encode file`: emits Base64 representing the exact bytes.
- `--transport-decode textfile`: reconstructs bytes into `textfile.decoded`.

The analyzer never trusts the extension. Confidence is evidence-based. A 100% result means a known signature matched; it is not a claim that every nested structure is decoded.
