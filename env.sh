# Source before building:  source env.sh
#
# The bare-metal build needs only Espressif's Rust toolchain. No ESP-IDF, no
# Python, no C toolchain.

if [ -f "$HOME/export-esp.sh" ]; then
    . "$HOME/export-esp.sh"
else
    echo "env.sh: ~/export-esp.sh not found - run ./setup.sh first" >&2
fi
