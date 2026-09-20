#!/usr/bin/env bash
# One-time toolchain setup.
#
# Xtensa is not an upstream rustc target, so we need Espressif's fork. That is
# the only requirement — the bare-metal stack (esp-hal/esp-radio) pulls in no
# ESP-IDF, no CMake/Ninja, and no Python.
#
# Every cargo call uses an explicit `+stable`: this directory's
# rust-toolchain.toml pins the `esp` toolchain, which does not exist until
# espup has run, so without the override setup cannot bootstrap itself.

set -euo pipefail

GRN=$'\e[32m'; YEL=$'\e[33m'; RST=$'\e[0m'
say()  { echo "${GRN}==>${RST} $*"; }
skip() { echo "${YEL}-->${RST} $* (already present)"; }

ARCH="x86_64-unknown-linux-gnu"
mkdir -p "$HOME/.cargo/bin"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

command -v rustup >/dev/null || { echo "Install Rust first: https://rustup.rs" >&2; exit 1; }
rustup toolchain list | grep -q '^stable' || rustup toolchain install stable

# Prebuilt binaries rather than `cargo install`: building espup from source
# pulls openssl-sys, which on Fedora compiles a vendored OpenSSL needing Perl's
# FindBin.pm - not installed by default, and the failure is opaque.
if command -v espup >/dev/null 2>&1; then skip espup; else
    say "Downloading espup"
    curl -sSfL --max-time 180 -o "$TMP/espup" \
        "https://github.com/esp-rs/espup/releases/latest/download/espup-$ARCH"
    install -m755 "$TMP/espup" "$HOME/.cargo/bin/espup"
fi

if command -v espflash >/dev/null 2>&1; then skip espflash; else
    say "Downloading espflash"
    curl -sSfL --max-time 180 -o "$TMP/ef.zip" \
        "https://github.com/esp-rs/espflash/releases/latest/download/espflash-$ARCH.zip"
    mkdir -p "$TMP/ef" && unzip -oq "$TMP/ef.zip" -d "$TMP/ef"
    install -m755 "$(find "$TMP/ef" -name espflash -type f | head -1)" "$HOME/.cargo/bin/espflash"
fi

if rustup toolchain list | grep -q '^esp'; then skip "esp toolchain"; else
    say "Installing the Xtensa Rust toolchain (multi-GB, be patient)"
    ( cd "$HOME" && espup install --targets esp32 )
fi

say "Done:  source env.sh && cargo run --release"
