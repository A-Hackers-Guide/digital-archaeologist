# Unknown-format research

The `--unknown` profile is intentionally conservative. It collects byte-level evidence and known signatures without pretending that an unrecognized blob has a known filesystem.

Future research stages should add:
1. Partition candidate discovery at arbitrary offsets.
2. Repeating-block and alignment analysis.
3. String and timestamp extraction.
4. Known-specimen comparison.
5. Hypothesis scoring with reproducible evidence.
6. Read-only virtual views before any filesystem-driver work.

A 100% signature confidence means the signature itself matched completely; it does **not** mean every internal structure has been decoded.
