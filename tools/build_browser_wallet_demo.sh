#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/demos/browser-wallet"
TARGET="thumbv6m-none-eabi"
TOOLCHAIN="1.98.0"

rustup target add --toolchain "$TOOLCHAIN" "$TARGET" >/dev/null
rustup component add --toolchain "$TOOLCHAIN" llvm-tools-preview >/dev/null

cargo +"$TOOLCHAIN" test --manifest-path "$DEMO/Cargo.toml"
CARGO_TARGET_THUMBV6M_NONE_EABI_RUSTFLAGS="-C link-arg=-Tlink.x" \
  cargo +"$TOOLCHAIN" build \
    --manifest-path "$DEMO/Cargo.toml" \
    --release \
    --features firmware \
    --target "$TARGET"

SYSROOT="$(rustc +"$TOOLCHAIN" --print sysroot)"
HOST="$(rustc +"$TOOLCHAIN" -vV | sed -n 's/^host: //p')"
OBJCOPY="$SYSROOT/lib/rustlib/$HOST/bin/llvm-objcopy"
ELF="$DEMO/target/$TARGET/release/hardware-wallet-browser-demo"
DIST="$DEMO/dist"

mkdir -p "$DIST"
"$OBJCOPY" -O ihex "$ELF" "$DIST/wallet-demo.hex"
cp "$ELF" "$DIST/wallet-demo.elf"

HEX_BYTES="$(wc -c < "$DIST/wallet-demo.hex")"
ELF_BYTES="$(wc -c < "$DIST/wallet-demo.elf")"
if (( HEX_BYTES < 1024 )); then
  echo "browser wallet HEX is unexpectedly small: ${HEX_BYTES} bytes" >&2
  exit 1
fi

printf 'browser wallet firmware: %s bytes HEX, %s bytes ELF\n' "$HEX_BYTES" "$ELF_BYTES"
