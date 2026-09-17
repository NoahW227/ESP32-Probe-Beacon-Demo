#!/usr/bin/env bash
# One-time toolchain setup for the ESP32-S3 wardriving firmware on Fedora.
#
# Building Rust for the Xtensa ESP32-S3 needs three things that are not on a
# stock Fedora box:
#   1. Espressif's fork of rustc/LLVM (Xtensa is not an upstream rustc target)
#   2. ESP-IDF v5.2.2 itself, which esp-idf-sys downloads and builds
#   3. A Python that ESP-IDF actually supports
#
# (3) is the sharp edge on Fedora 44: the system Python is 3.14, which ESP-IDF
# 5.2 predates and rejects. We install python3.12 alongside it and expose it to
# the build through a shim directory, without touching the system default.
#
# NOTE: every cargo call here uses an explicit `+stable`. This directory has a
# rust-toolchain.toml pinning the `esp` toolchain, which does not exist until
# the espup step below has run - without the override, rustup refuses to run
# cargo at all and setup cannot bootstrap itself.

set -euo pipefail

GRN=$'\e[32m'; YEL=$'\e[33m'; RST=$'\e[0m'
say()  { echo "${GRN}==>${RST} $*"; }
skip() { echo "${YEL}-->${RST} $* (already present, skipping)"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM="$HERE/.toolchain/pybin"

# --- 0. sanity -----------------------------------------------------------
if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup not found. Install Rust from https://rustup.rs first." >&2
    exit 1
fi
if ! rustup toolchain list 2>/dev/null | grep -q '^stable'; then
    say "Installing the stable Rust toolchain (needed to bootstrap)"
    rustup toolchain install stable
fi

# --- 1. system packages --------------------------------------------------
# ninja        : ESP-IDF's build generator
# libusb1-devel: espflash links against it
# python3.12   : see header
say "Installing system packages (needs sudo)..."
sudo dnf install -y ninja-build libusb1-devel python3.12 python3.12-devel curl unzip

# --- 2. python shim ------------------------------------------------------
# ESP-IDF's installer builds a venv from whatever "python3" it finds first on
# PATH. Rather than changing the system default (which would break Fedora
# tooling), we put a single symlink in a directory we prepend at build time.
say "Creating python3.12 shim at $SHIM"
mkdir -p "$SHIM"
ln -sf /usr/bin/python3.12 "$SHIM/python3"
ln -sf /usr/bin/python3.12 "$SHIM/python"

# --- 3. rust side --------------------------------------------------------
# We install espup and espflash from Espressif's PREBUILT release binaries
# rather than `cargo install`.
#
# Why: `cargo install espup` pulls openssl-sys, which on Fedora tries to
# compile a vendored OpenSSL from source. That needs Perl's FindBin.pm, and
# Fedora splits Perl into micro-packages so FindBin is not installed by
# default. The build dies with a misleading "failed to build OpenSSL from
# source". Prebuilt binaries skip the whole problem, need no sudo, and are
# much faster.
#
# ldproxy is a tiny crate with no openssl dependency, so cargo install is fine
# there - but it still needs +stable, because this directory's
# rust-toolchain.toml pins the `esp` toolchain that does not exist yet.

ARCH="x86_64-unknown-linux-gnu"
mkdir -p "$HOME/.cargo/bin"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if command -v espup >/dev/null 2>&1; then
    skip "espup"
else
    say "Downloading prebuilt espup"
    curl -sSfL --max-time 180 -o "$TMP/espup" \
        "https://github.com/esp-rs/espup/releases/latest/download/espup-$ARCH"
    install -m755 "$TMP/espup" "$HOME/.cargo/bin/espup"
fi

if command -v espflash >/dev/null 2>&1; then
    skip "espflash"
else
    say "Downloading prebuilt espflash"
    curl -sSfL --max-time 180 -o "$TMP/espflash.zip" \
        "https://github.com/esp-rs/espflash/releases/latest/download/espflash-$ARCH.zip"
    mkdir -p "$TMP/ef"
    unzip -o -q "$TMP/espflash.zip" -d "$TMP/ef"
    install -m755 "$(find "$TMP/ef" -name espflash -type f | head -1)" \
        "$HOME/.cargo/bin/espflash"
fi

if command -v ldproxy >/dev/null 2>&1; then
    skip "ldproxy"
else
    say "Installing ldproxy"
    ( cd "$HOME" && cargo +stable install ldproxy --locked )
fi

if rustup toolchain list 2>/dev/null | grep -q '^esp'; then
    skip "esp Rust toolchain"
else
    say "Installing the Xtensa Rust toolchain (multi-GB download, be patient)..."
    ( cd "$HOME" && espup install --targets esp32s3 )
fi

# --- 4. udev -------------------------------------------------------------
# This board enumerates as /dev/ttyUSB0 via a USB-UART bridge. The rule below
# also covers the native USB Serial/JTAG path in case you swap boards.
say "Installing udev rules"
sudo tee /etc/udev/rules.d/60-esp32.rules >/dev/null <<'RULE'
# Espressif native USB Serial/JTAG
SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", MODE="0666", GROUP="dialout"
# Common USB-UART bridges found on S3 devkits
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", MODE="0666", GROUP="dialout"
SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", MODE="0666", GROUP="dialout"
RULE
sudo udevadm control --reload-rules && sudo udevadm trigger

say "Done. Source the environment before building:"
echo
echo "    source $HERE/env.sh"
echo "    cargo build --release"
echo
