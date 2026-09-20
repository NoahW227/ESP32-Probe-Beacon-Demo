#!/usr/bin/env bash
# Record the firmware's JSON stream to a timestamped file.
#
#   ./capture.sh [seconds] [port]      default: 30s on /dev/ttyUSB0
#
# Output goes to captures/capture-YYYYmmdd-HHMMSS.jsonl. Names are unique per
# run and the script refuses to clobber an existing file, so hand-curated
# captures (demo-fallback.jsonl) can never be overwritten.

set -euo pipefail

SECS="${1:-30}"
PORT="${2:-/dev/ttyUSB0}"
BAUD="${BAUD:-115200}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/captures/capture-$(date +%Y%m%d-%H%M%S).jsonl"
mkdir -p "$HERE/captures"

[ -e "$OUT" ] && { echo "refusing to overwrite $OUT" >&2; exit 1; }
[ -c "$PORT" ] || { echo "$PORT not found - is the board plugged in?" >&2; exit 1; }

echo "capturing ${SECS}s from $PORT at $BAUD -> ${OUT#$HERE/}"

# Serial settings revert when the last handle on the port closes, so stty
# followed by a separate cat races and yields corrupt data. Hold the fd open
# across both.
exec 3<>"$PORT"
stty -F "$PORT" "$BAUD" raw -echo -echoe -echok -crtscts -ixon
timeout "$SECS" cat <&3 > "$OUT.raw" || true
exec 3>&-

# Keep only well-formed JSON lines; boot chatter from the ROM bootloader shares
# the wire and is not valid JSON.
tr -d '\r' < "$OUT.raw" | grep '^{' > "$OUT" || true
rm -f "$OUT.raw"

echo "wrote $(wc -l < "$OUT") records to ${OUT#$HERE/}"
