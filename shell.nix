{ pkgs ? import <nixpkgs> {}
, crossPkgs ? import <nixpkgs> {}
, enableLibcxx ? false # Whether to use libc++ toolchain and libraries instead of libstdc++
, minimal ? false # Whether to create minimal shell without extra tools (faster when cross compiling)
, capnprotoVersion ? null
, capnprotoSanitizers ? null # Optional sanitizers to build cap'n proto with
, cmakeVersion ? null
, libcxxSanitizers ? null # Optional LLVM_USE_SANITIZER value to use for libc++, see https://llvm.org/docs/CMake.html
, enableWine ? false # Whether to add wine64 for running cross-compiled Windows binaries
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
    "0.7.0" = "sha256-Y/7dUOQPDHjniuKNRw3j8dG1NI9f/aRWpf8V0WzV9k8=";
    "0.7.1" = "sha256-3cBpVmpvCXyqPUXDp12vCFCk32ZXWpkdOliNH37UwWE=";
    "0.8.0" = "sha256-rfiqN83begjJ9eYjtr21/tk1GJBjmeVfa3C3dZBJ93w=";
    "0.8.1" = "sha256-OZqNVYdyszro5rIe+w6YN00g6y8U/1b8dKYc214q/2o=";
    "0.9.0" = "sha256-yhbDcWUe6jp5PbIXzn5EoKabXiWN8lnS08hyfxUgEQ0=";
    "0.9.2" = "sha256-BspWOPZcP5nCTvmsDE62Zutox+aY5pw42d6hpH3v4cM=";
    "0.10.0" = "sha256-++F4l54OMTDnJ+FO3kV/Y/VLobKVRk461dopanuU3IQ=";
    "0.10.4" = "sha256-45sxnVyyYIw9i3sbFZ1naBMoUzkpP21WarzR5crg4X8=";
    "1.0.0" = "sha256-NLTFJdeOzqhk4ATvkc17Sh6g/junzqYBBEoXYGH/czo=";
    "1.0.2" = "sha256-LVdkqVBTeh8JZ1McdVNtRcnFVwEJRNjt0JV2l7RkuO8=";
    "1.1.0" = "sha256-gxkko7LFyJNlxpTS+CWOd/p9x/778/kNIXfpDGiKM2A=";
    "1.2.0" = "sha256-aDcn4bLZGq8915/NPPQsN5Jv8FRWd8cAspkG3078psc=";
    "1.3.0" = "sha256-fvZzNDBZr73U+xbj1LhVj1qWZyNmblKluh7lhacV+6I=";
    "1.4.0" = "sha256-CuhKOJwU+QG25lRR8F7ina+DV45ZlLzg/UJ2swf2tZ0=";
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
  } // (lib.optionalAttrs (lib.versionOlder capnprotoVersion "0.10") {
    env = { }; # Drop -std=c++20 flag forced by nixpkgs
  }));
  # Native build of the same capnproto version, used as a build-time helper
  # when cross-compiling so capnpc generates schemas matching the cross headers.
  capnprotoNative = if capnprotoVersion == null then pkgs.capnproto else pkgs.capnproto.overrideAttrs (old: {
    version = capnprotoVersion;
    src = pkgs.fetchFromGitHub {
      owner = "capnproto";
      repo  = "capnproto";
      rev   = "v${capnprotoVersion}";
      hash  = lib.attrByPath [capnprotoVersion] "" capnprotoHashes;
    };
    patches = lib.optionals (lib.versionAtLeast capnprotoVersion "0.9.0" && lib.versionOlder capnprotoVersion "0.10.4") [ ./ci/patches/spaceship.patch ];
  } // (lib.optionalAttrs (lib.versionOlder capnprotoVersion "0.10") {
    env = { }; # Drop -std=c++20 flag forced by nixpkgs
  }));
  # mingw with mcf thread model requires _WIN32_WINNT to be defined before
  # any libstdc++ thread headers are included. See the patch header for
  # the rationale behind capnproto-wine-invalid-function.patch.
  capnprotoPatched = capnprotoBase.overrideAttrs (old: lib.optionalAttrs crossPkgs.stdenv.hostPlatform.isMinGW {
    patches = (old.patches or []) ++ [
      ./ci/patches/capnproto-wine-invalid-function.patch
    ];
    env = (old.env or { }) // {
      NIX_CFLAGS_COMPILE = lib.concatStringsSep " " [
        (old.env.NIX_CFLAGS_COMPILE or "")
        "-D_WIN32_WINNT=0x0601"
      ];
    };
  });
  capnproto = (capnprotoPatched.overrideAttrs (old: lib.optionalAttrs (capnprotoSanitizers != null) {
    env = (old.env or { }) // {
      CXXFLAGS =
        lib.concatStringsSep " " [
          (old.env.CXXFLAGS or "")
          "-fsanitize=${capnprotoSanitizers}"
          "-fno-omit-frame-pointer"
          "-g"
        ];
    };
  })).override (
    if enableLibcxx then { clangStdenv = llvm.libcxxStdenv; }
    # nixpkgs forces capnproto to be built with clangStdenv, but the mingw
    # clang wrapper auto-adds `-lgcc_s` to the link line, which doesn't exist
    # in the mingw GCC runtime layout (see nixpkgs#177129). Fall back to the
    # GCC cross stdenv when cross-compiling to mingw.
    else if crossPkgs.stdenv.hostPlatform.isMinGW then { clangStdenv = crossPkgs.stdenv; }
    else { });
  clang = if enableLibcxx then llvm.libcxxClang else llvm.clang;
  clang-tools = llvm.clang-tools.override { inherit enableLibcxx; };
  cmakeHashes = {
    "3.12.4" = "sha256-UlVYS/0EPrcXViz/iULUcvHA5GecSUHYS6raqbKOMZQ=";
  };
  cmakeBuild = if cmakeVersion == null then pkgs.cmake else (pkgs.cmake.overrideAttrs (old: {
    version = cmakeVersion;
    src = pkgs.fetchurl {
      url = "https://cmake.org/files/v${lib.versions.majorMinor cmakeVersion}/cmake-${cmakeVersion}.tar.gz";
      hash = lib.attrByPath [cmakeVersion] "" cmakeHashes;
    };
    patches = [];
  })).override { isMinimalBuild = true; };
in crossPkgs.mkShell ({
  buildInputs = [
    capnproto
  ];
  nativeBuildInputs = with pkgs; [
    cmakeBuild
    include-what-you-use
    ninja
  ] ++ lib.optionals (!minimal) [
    clang
    clang-tools
  ] ++ lib.optional enableWine pkgs.wineWowPackages.stable
    # When cross-compiling, also expose a native capnp/capnpc-c++ on PATH so
    # build-time code generators (capnp_generate_cpp) can run on the build host
    # instead of trying to execute target-arch binaries directly.
    ++ lib.optional (crossPkgs.stdenv.hostPlatform != crossPkgs.stdenv.buildPlatform) capnprotoNative;

  # Tell IWYU where its libc++ mapping lives
  IWYU_MAPPING_FILE = if enableLibcxx then "${llvm.libcxx.dev}/include/c++/v1/libcxx.imp" else null;
} // lib.optionalAttrs (enableWine && crossPkgs.stdenv.hostPlatform.isMinGW) {
  # Cross-compiled .exe files run under wine64 need the capnproto and mingw
  # thread runtime DLLs at startup. Wine searches the .exe directory and the
  # Windows system directory for PE imports, so symlink the required DLLs
  # into $WINEPREFIX/drive_c/windows/system32 when entering the shell.
  shellHook = ''
    if [ -n "''${WINEPREFIX-}" ]; then
      _mp_sys32="$WINEPREFIX/drive_c/windows/system32"
      mkdir -p "$_mp_sys32"
      for _d in ${capnproto}/bin ${crossPkgs.windows.mcfgthreads}/bin; do
        for _dll in "$_d"/*.dll; do
          [ -e "$_dll" ] && ln -sf "$_dll" "$_mp_sys32/"
        done
      done
      unset _mp_sys32 _d _dll
    fi
  '';
})
