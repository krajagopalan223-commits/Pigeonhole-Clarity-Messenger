#!/usr/bin/env bash
#
# Build the clarity-core native library for a target platform and drop it where
# the Flutter build expects it. Run from the repo root.
#
#   tool/build_rust.sh linux     # host Linux desktop
#   tool/build_rust.sh android   # all Android ABIs (needs cargo-ndk + NDK)
#   tool/build_rust.sh ios       # iOS device + simulator static libs
#
# See app/README.md for how each platform links the result.

set -euo pipefail

TARGET="${1:-linux}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

case "$TARGET" in
  linux)
    cargo build -p clarity-ffi --release
    DEST="$ROOT/app/linux/lib"
    mkdir -p "$DEST"
    cp "$ROOT/target/release/libclarity_ffi.so" "$DEST/"
    echo "Copied libclarity_ffi.so -> $DEST"
    echo "Ensure app/linux/CMakeLists.txt installs it as a bundled library (see app/README.md)."
    ;;

  android)
    # Requires: cargo install cargo-ndk && rustup target add \
    #   aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
    command -v cargo-ndk >/dev/null || { echo "cargo-ndk not found; install it first"; exit 1; }
    JNI="$ROOT/app/android/app/src/main/jniLibs"
    mkdir -p "$JNI"
    cargo ndk \
      -t arm64-v8a -t armeabi-v7a -t x86_64 \
      -o "$JNI" \
      build --release -p clarity-ffi
    echo "Android .so files written under $JNI"
    ;;

  ios)
    # Requires: rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
    cargo build -p clarity-ffi --release --target aarch64-apple-ios
    cargo build -p clarity-ffi --release --target aarch64-apple-ios-sim
    OUT="$ROOT/app/ios/Frameworks"
    mkdir -p "$OUT"
    cp "$ROOT/target/aarch64-apple-ios/release/libclarity_ffi.a" "$OUT/libclarity_ffi-device.a"
    cp "$ROOT/target/aarch64-apple-ios-sim/release/libclarity_ffi.a" "$OUT/libclarity_ffi-sim.a"
    echo "iOS static libs written to $OUT"
    echo "Link the appropriate .a in Xcode (see app/README.md)."
    ;;

  *)
    echo "Unknown target: $TARGET (expected linux|android|ios)"
    exit 1
    ;;
esac
