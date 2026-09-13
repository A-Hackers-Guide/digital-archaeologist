# Contributing

1. Build with CMake.
2. Run the full CTest suite.
3. Add a regression test for new detection behavior.
4. Keep analysis read-only.
5. Document confidence/evidence for new heuristics.
6. Do not add code that silently mounts, modifies, or installs filesystem drivers.

Pull requests should explain what new evidence the analyzer understands and how false positives are controlled.
