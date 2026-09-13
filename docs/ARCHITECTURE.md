# Architecture

```text
Input
  |
  +-- raw byte reader
  +-- signature detector
  +-- entropy/statistics engine
  +-- structure probes
  +-- partition evidence
  +-- strings/search engine
  +-- integrity hashing
  +-- confidence/evidence layer
  +-- report serializers
  |
  +--> human report / JSON / transport output
```

The v2 CLI keeps the core analysis dependency-light. The detector is deliberately conservative: a strong signature produces high confidence; weak statistical evidence produces lower confidence and is explicitly labeled as unresolved.

Future modules can add filesystem parsers, nested-container traversal, streaming I/O, carving rules, and pluggable format signatures without changing the command surface.
