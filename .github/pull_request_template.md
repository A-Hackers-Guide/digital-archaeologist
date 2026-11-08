<!-- Thanks for sending a PR. Drop sections that don't apply. -->

## What this changes



## Why



## Scope

- [ ] Analyzer / detection
- [ ] Carve / container walk
- [ ] Hashing / CRC
- [ ] Strings / timeline
- [ ] CLI
- [ ] Tests
- [ ] Docs
- [ ] CI

## Checklist

- [ ] New detection? Added a fixture to `tests/detect_test.cpp`
- [ ] New format? Updated `docs/formats.md`
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] ASan + UBSan still green locally (`cmake -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined"`)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
