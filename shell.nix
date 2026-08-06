{ pkgs ? import <nixpkgs> {}
, crossPkgs ? import <nixpkgs> {}
, enableLibcxx ? false # Whether to use libc++ toolchain and libraries instead of libstdc++
, minimal ? false # Whether to create minimal shell without extra tools (faster when cross compiling)
, capnprotoVersion ? null
, capnprotoSanitizers ? null # Optional sanitizers to build cap'n proto with
, cmakeVersion ? null
, gccVersion ? null
, libcxxSanitizers ? null # Optional LLVM_USE_SANITIZER value to use for libc++, see https://llvm.org/docs/CMake.html
}:

let
  lib  = pkgs.lib;
  llvmBase = crossPkgs.llvmPackages_21;
  llvm = llvmBase // lib.optionalAttrs (libcxxSanitizers != null) {
    libcxx = llvmBase.libcxx.override {
      devExtraCmakeFlags = [ "-DLLVM_USE_SANITIZER=${libcxxSanitizers}" ];
    };
  };
  capnprotoHashes = {
    "0.9.0" = "sha256-yhbDcWUe6jp5PbIXzn5EoKabXiWN8lnS08hyfxUgEQ0=";
    "0.9.2" = "sha256-BspWOPZcP5nCTvmsDE62Zutox+aY5pw42d6hpH3v4cM=";
    "0.10.0" = "sha256-++F4l54OMTDnJ+FO3kV/Y/VLobKVRk461dopanuU3IQ=";
    "0.10.4" = "sha256-45sxnVyyYIw9i3sbFZ1naBMoUzkpP21WarzR5crg4X8=";
    "1.0.0" = "sha256-NLTFJdeOzqhk4ATvkc17Sh6g/junzqYBBEoXYGH/czo=";
    "1.0.2" = "sha256-LVdkqVBTeh8JZ1McdVNtRcnFVwEJRNjt0JV2l7RkuO8=";
    "1.1.0" = "sha256-gxkko7LFyJNlxpTS+CWOd/p9x/778/kNIXfpDGiKM2A=";
    "1.2.0" = "sha256-aDcn4bLZGq8915/NPPQsN5Jv8FRWd8cAspkG3078psc=";
  };
  capnprotoBase = if capnprotoVersion == null then crossPkgs.capnproto else crossPkgs.capnproto.overrideAttrs (old: {
    version = capnprotoVersion;
    src = crossPkgs.fetchFromGitHub {
      owner = "capnproto";
      repo  = "capnproto";
      rev   = "v${capnprotoVersion}";
      hash  = lib.attrByPath [capnprotoVersion] "" capnprotoHashes;
    };
    patches = lib.optionals (lib.versionAtLeast capnprotoVersion "0.9.0" && lib.versionOlder capnprotoVersion "0.10.4") [ ./ci/patches/spaceship.patch ];
    cmakeFlags = (old.cmakeFlags or []) ++ (lib.optionals (lib.versionAtLeast "1.1.0" capnprotoVersion) ["-DCMAKE_POLICY_VERSION_MINIMUM=3.5"]);
  } // (lib.optionalAttrs (lib.versionOlder capnprotoVersion "0.10") {
    env = { }; # Drop -std=c++20 flag forced by nixpkgs
  }));
  capnproto = (capnprotoBase.overrideAttrs (old: lib.optionalAttrs (capnprotoSanitizers != null) {
    env = (old.env or { }) // {
      CXXFLAGS =
        lib.concatStringsSep " " [
          (old.env.CXXFLAGS or "")
          "-fsanitize=${capnprotoSanitizers}"
          "-fno-omit-frame-pointer"
          "-g"
        ];
    };
  })).override (lib.optionalAttrs enableLibcxx { clangStdenv = llvm.libcxxStdenv; });
  clang = if enableLibcxx then llvm.libcxxClang else llvm.clang;
  clang-tools = llvm.clang-tools.override { inherit enableLibcxx; };
  # IWYU parses source files with its own embedded clang frontend, locating
  # standard library headers through CPATH/CPLUS_INCLUDE_PATH variables set by
  # its nixpkgs wrapper script:
  # https://github.com/NixOS/nixpkgs/blob/master/pkgs/development/tools/analysis/include-what-you-use/wrapper
  # The wrapper derives those variables from the clang recorded in the
  # derivation's `clang` attribute, which defaults to the toolchain IWYU was
  # built against (libstdc++-flavored on Linux), not the toolchain this shell
  # uses. Rebind it to this shell's compiler so IWYU resolves the same
  # standard library the build uses.
  #
  # Mixing pkgs and crossPkgs here is intentional: IWYU comes from pkgs
  # because it runs on the build machine, while `clang` comes from crossPkgs
  # (via llvm) so that in a cross shell IWYU is baked with the cross
  # toolchain's target headers — what it needs to analyze a cross build.
  include-what-you-use = pkgs.include-what-you-use.overrideAttrs (old: {
    inherit clang;
  });
  cmakeHashes = {
    "3.12.4" = "sha256-UlVYS/0EPrcXViz/iULUcvHA5GecSUHYS6raqbKOMZQ=";
  };
  gcc = if gccVersion == null then null else builtins.getAttr ("gcc" + gccVersion) pkgs;
  cmakeBuild = if cmakeVersion == null then pkgs.cmake else (pkgs.cmake.overrideAttrs (old: {
    version = cmakeVersion;
    src = pkgs.fetchurl {
      url = "https://cmake.org/files/v${lib.versions.majorMinor cmakeVersion}/cmake-${cmakeVersion}.tar.gz";
      hash = lib.attrByPath [cmakeVersion] "" cmakeHashes;
    };
    patches = [];
  })).override { isMinimalBuild = true; };
in crossPkgs.mkShell {
  buildInputs = [
    capnproto
  ];
  nativeBuildInputs = with pkgs; [
    cmakeBuild
    ninja
  ] ++ lib.optional (gcc != null) gcc ++ lib.optionals (!minimal) [
    # List clang-tools before clang so its wrapped tools take PATH priority
    # (the first package in the list wins). Both packages provide the same
    # tools (clangd, clang-tidy, clang-check, ...), but the clang package's
    # copies are unwrapped and cannot find standard library headers like
    # <cstddef>, while the clang-tools copies are wrapper scripts that add
    # the C and C++ standard library include paths.
    # https://web.archive.org/web/20260311024938/https://blog.kotatsu.dev/posts/2024-04-10-nixpkgs-clangd-missing-headers/
    # https://github.com/NixOS/nixpkgs/issues/76486
    clang-tools
    clang
    include-what-you-use
  ];

  CC = if gcc == null then null else "${gcc}/bin/gcc";
  CXX = if gcc == null then null else "${gcc}/bin/g++";

  # Tell IWYU where its libc++ mapping file lives. libcxx.imp maps
  # libc++-internal detail headers (e.g. <__vector/vector.h>) to the public
  # headers IWYU should suggest instead. IWYU only applies mapping tables
  # compiled into its binary unless a mapping file is passed explicitly — it
  # does not discover the libcxx.imp shipped alongside the headers it parses —
  # so CMakeLists.txt forwards this variable via -Xiwyu --mapping_file. Taking
  # the file from llvm.libcxx keeps it consistent with the headers IWYU parses
  # via the include-what-you-use override above.
  IWYU_MAPPING_FILE = if enableLibcxx then "${llvm.libcxx.dev}/include/c++/v1/libcxx.imp" else null;
}
