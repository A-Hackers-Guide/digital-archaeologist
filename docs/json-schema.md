# JSON output schema

`archaeologist --json <file>` writes exactly one JSON object to stdout, followed by a newline.

```json
{
  "path": "firmware.bin",
  "size": 16777216,
  "sha256": "...64 hex chars...",
  "entropy": 7.9124,
  "printable_ratio": 0.024,
  "bytes_scanned": 16777216,
  "truncated": false,
  "dominant_byte": 0,
  "dominant_byte_count": 123456,
  "detections": [
    {
      "category": "image",
      "format": "PNG",
      "confidence": 100,
      "mime": "image/png",
      "evidence": [
        { "label": "signature", "detail": "PNG magic", "weight": 100 }
      ]
    }
  ],
  "notes": [
    "High entropy: data may be compressed, encrypted, packed, or otherwise binary-dense."
  ]
}
```

## Fields

| Field | Type | Meaning |
|---|---|---|
| `path` | string | Input path as supplied on the command line |
| `size` | integer | File size in bytes (as reported by the filesystem) |
| `sha256` | string | SHA-256 over the **whole file**, streamed; 64 lowercase hex chars |
| `entropy` | number | Shannon entropy in bits/byte, over the loaded window (0 – 8) |
| `printable_ratio` | number | Fraction of bytes that are ASCII printable or tab/CR/LF (0 – 1) |
| `bytes_scanned` | integer | How many bytes structural analysis actually looked at |
| `truncated` | boolean | True if the file exceeded `--max-size` (SHA-256 still covers the full file) |
| `dominant_byte` | integer | The most frequent byte value (0 – 255) |
| `dominant_byte_count` | integer | How many times the dominant byte appears |
| `detections` | array | One entry per matched signature, most specific first |
| `detections[].category` | string | `executable` / `image` / `filesystem` / etc. |
| `detections[].format` | string | Human name of the format |
| `detections[].confidence` | integer | 0 – 100 |
| `detections[].mime` | string | Best-guess MIME, or `""` if no stable MIME |
| `detections[].evidence` | array | One `{label, detail, weight}` per contributing signal |
| `notes` | array | Free-form human-readable notes (entropy class, truncation, etc.) |

## Stability

- Field **names** are stable within a major version.
- Field **order** inside a `detections` entry is stable.
- The `detections` array is ordered most-specific-first by the detector; downstream consumers should **not** rely on any specific ordering beyond that.
- `confidence` is a soft score. A value of 100 means "the magic matched exactly"; it is not a cryptographic proof that the file is well-formed.
- Numbers are plain JSON numbers. `entropy` has six fractional digits; `printable_ratio` has the platform default.
