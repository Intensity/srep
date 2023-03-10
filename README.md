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

## Description

Description: https://web.archive.org/web/20161223135216/http://freearc.org/research/SREP.aspx

## Last known commit

```
changeset:   3011:48624cadaac2
tag:         tip
date:        Sun Nov 16 15:58:12 2014 +0300
summary:     Compression: a few more fixes
```
