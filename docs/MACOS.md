# macOS / Xcode

The repository includes `macos/DigitalArchaeologist.xcodeproj` as an Xcode-oriented build entry point.

The project intentionally requires an active Apple developer directory. Apple documents that Command Line Tools can be selected as the active developer directory with `xcode-select`, and that the tools support terminal and CI builds. citeturn0search0turn0search2

## Command Line Tools only

```sh
xcode-select --print-path
xcrun --find clang++
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

If the active developer directory is missing, install Apple's Command Line Tools and select `/Library/Developer/CommandLineTools` as appropriate for your machine.

## Xcode

Open the project in Xcode and run the `DigitalArchaeologist` scheme. The build phase invokes the repository CMake build after validating the developer tools.
