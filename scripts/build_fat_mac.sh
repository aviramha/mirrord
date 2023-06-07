#!/bin/sh
# This script builds a fat binary for Mac OS X.
# Output will be in target/universal-apple-darwin/debug/mirrord
# If compilation fails, try running:
# rustup target add --toolchain nightly-2023-03-29 x86_64-apple-darwin

set -e
cargo +nightly-2023-03-29 clean -p frida-gum
cargo +nightly-2023-03-29 clean -p frida-gum-sys
cargo +nightly-2023-03-29 build -p mirrord-layer --target=aarch64-apple-darwin
codesign -f -s - target/aarch64-apple-darwin/debug/libmirrord_layer.dylib
mkdir -p target/universal-apple-darwin/debug
cp target/aarch64-apple-darwin/debug/libmirrord_layer.dylib target/universal-apple-darwin/debug/libmirrord_layer.dylib
MIRRORD_LAYER_FILE=../../../target/universal-apple-darwin/debug/libmirrord_layer.dylib cargo +nightly-2023-03-29 build -p mirrord --target=aarch64-apple-darwin
cp target/aarch64-apple-darwin/debug/mirrord target/universal-apple-darwin/debug/mirrord 
codesign -f -s - target/universal-apple-darwin/debug/mirrord

target/universal-apple-darwin/debug/mirrord exec -t pod/ip-visit-counter-6cf56d9ddf-tzbzp node