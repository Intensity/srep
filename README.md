# SuperREP: huge-dictionary LZ77 preprocessor

- SREP 3.93a beta (October 11, 2014): authored by Bulat Ziganshin

This is an unofficial repackage of the last known commit from the former
Mercurial repository.

To build and install:

```bash
  $ make
  # make install
```

A `PREFIX` may be provided to the `make` argument. This has been tested
on Debian Linux 11 and FreeBSD on Intel architecture. Beyond that, your
mileage may vary and some modifications to the build may be required. The
source files have been trimmed to include only the dependencies needed
for compilation, and the endian check was removed since it did not appear
to work with FreeBSD/clang.

## macOS (Apple Silicon and Intel)

Install the Apple Command Line Tools if they are not already available:

```bash
xcode-select --install
```

Build with the system compiler and run directly from the checkout:

```bash
make
./bin/srep -d input.srep output
```

The Makefile selects dynamic linking on macOS, locates the active SDK with
`xcrun`, and enables SSE2 flags only for x86 compiler targets. No Homebrew
packages, Windows environment, or Rosetta are needed for a native ARM64 build.
The macOS thread CPU timer requires macOS 10.12 or later.

Run the compression/decompression checks with Python 3:

```bash
python3 tests/roundtrip.py
```

CI runs the same checks on Linux x86-64, macOS ARM64, and macOS Intel.
The checks use generated data only; no external archives are required.

## Description

Description: https://web.archive.org/web/20161223135216/http://freearc.org/research/SREP.aspx

## Last known commit

```
changeset:   3011:48624cadaac2
tag:         tip
date:        Sun Nov 16 15:58:12 2014 +0300
summary:     Compression: a few more fixes
```
