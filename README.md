# libmultiprocess (support branch)

This branch contains CI scripts, documentation, and examples supporting the
libmultiprocess library.

Contents:

- [`ci/`](ci/) — CI scripts, configs, and patches
- [`doc/`](doc/) — design, usage, and installation documentation
- [`example/`](example/) — example C++ code
- [`CMakeLists.txt`](CMakeLists.txt) — CMake project for building example code
- [`shell.nix`](shell.nix) — Nix development environment

The `CMakeLists.txt` file assumes it is checked out to a subdirectory of the
libmultiprocess library source code (this can be controlled with the
`MP_SOURCE_DIR` option), and the library can be found one level up.

See [ci/README.md](ci/README.md) for instructions on running CI jobs locally.
