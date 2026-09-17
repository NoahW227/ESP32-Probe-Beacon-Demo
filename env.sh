# Source this before building:  source env.sh
#
# Order matters: the python3.12 shim must come before /usr/bin so ESP-IDF's
# installer doesn't pick up Fedora's Python 3.14, which it does not support.

_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PATH="$_here/.toolchain/pybin:$PATH"

# Espressif's Xtensa rust toolchain + LLVM, written by `espup install`.
if [ -f "$HOME/export-esp.sh" ]; then
    . "$HOME/export-esp.sh"
else
    echo "env.sh: ~/export-esp.sh not found - run ./setup.sh first" >&2
fi

# Keep the multi-GB ESP-IDF checkout inside the project rather than $HOME, so
# it's easy to find and easy to delete.
export ESP_IDF_TOOLS_INSTALL_DIR="workspace"

echo "esp env ready: python=$(python3 --version 2>&1), rustc=$(rustc +esp --version 2>&1 | head -1)"
