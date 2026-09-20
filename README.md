# wardrive-fw

Passive 802.11 management-frame sniffer for the ESP32. Emits newline-delimited
JSON on the serial console; a host program consumes it.

## Stack

Bare-metal Rust — no ESP-IDF, no FreeRTOS, no C toolchain.

| crate | role |
| --- | --- |
| `esp-hal` 1.1 | peripherals, timers, clocks |
| `esp-radio` 0.18 | WiFi driver and promiscuous-mode sniffer |
| `esp-rtos` 0.3 | scheduler (esp-radio panics without one) |
| `ieee80211` | 802.11 frame and element parsing |
| `serde` + `serde_json` | wire format |

`esp-radio` supersedes `esp-wifi`, which now only builds against `esp-hal`
1.0.0-rc.0 — it references a HAL feature renamed after that release.

The firmware contains **no `unsafe`**.

## Why it's built this way

**We never associate.** Association pins the radio to the AP's channel, which
would kill channel hopping. That is also why the host link is serial rather
than WiFi.

**Beacons are aggregated on-device.** Every AP beacons ~10x/second; twenty APs
is ~200 near-identical frames/second. The firmware keeps a BSSID table and
emits one row per AP per second with the strongest RSSI in that window.

**Named probe requests are never dropped.** Wildcard (empty-SSID) probes are
the bulk of client traffic and are individually uninteresting, so they are
budgeted at 150/sec. A probe carrying a real SSID bypasses the budget — those
are rare and are the point.

## Setup

    ./setup.sh        # Espressif Rust toolchain (Xtensa is not upstream)
    source env.sh     # in every new shell

## Build and flash

    source env.sh
    cargo build --release
    cargo run --release      # flash + monitor

Incremental rebuilds are ~3 seconds.

## This board

Classic **ESP32** (`esp32 rev v3.1`, WiFi+BT, 4 MB flash), not an ESP32-S3. It
enumerates as `/dev/ttyUSB0` via a CH340/CP210x bridge; the ESP32 has no native
USB, so UART0 is the only console.

Console runs at the bootloader default **115200**. Measured load is ~41% of
that. To retarget an actual S3, change `target` and `MCU` in
`.cargo/config.toml`; `main.rs` needs no changes.

**Flash at the default baud.** This CH340 fails at 460800 with `Timeout while
running ReadReg command`. Flashing baud is unrelated to console baud.

## Capturing a stream by hand

Serial settings revert when the last handle on the port closes, so `stty`
followed by a separate `cat` races and yields corrupt data. Hold the fd open:

    exec 3<>/dev/ttyUSB0
    stty -F /dev/ttyUSB0 115200 raw -echo -echoe -echok -crtscts -ixon
    timeout 30 cat <&3 > capture.jsonl
    exec 3>&-

## Host display

    ./host/host.py                                    # live from the board
    ./host/host.py --replay captures/demo-fallback.jsonl
    ./host/host.py --watch "Smith Family WiFi"        # pin a planted SSID

Then open <http://127.0.0.1:8000/>.

Standard library only — no pip, no sudo. We never write to the serial port, so
after `termios` sets the line discipline it reads as a plain file, which is why
`pyserial` isn't needed.

Layout: access points by signal strength (the room's own AP sorts to the top),
probe requests as a live feed, and a pinned panel of the network names devices
are asking for. That last panel is the point of the demo and never scrolls, so
a rare named probe can't vanish mid-sentence.

Keys: `M` reveals full MACs, `+`/`-` resize for the projector.

MACs are redacted by default to `Vendor:hash` (`Sony:cc33`). Colour encodes
what kind of address it is, and the label agrees with it:

| shown | colour | meaning |
| --- | --- | --- |
| `Sony:cc33` | blue | real hardware address, manufacturer known |
| `(random):a471` | purple | locally-administered bit set — the device made this address up, so there is no manufacturer to name |
| `38:8d:3d:fd13` | dim blue | real address, but the OUI is not in the registry |

Vendors come from the system IEEE registry (`/usr/share/hwdata/oui.txt`, ~40k
entries) when present, else a small built-in list. Redaction never depends on
the lookup: the device-specific half of the address is hidden either way.

`--replay` paces playback from the recorded `ts` deltas and loops, so a capture
looks live on the projector. Use it if the venue's RF is dead.

## Output schema (schema: 1)

One JSON object per line; skip anything not starting with `{`.

    {"t":"beacon","ts":12345,"bssid":"aa:bb:cc:dd:ee:ff","ssid":"CoffeeShop",
     "hidden":false,"rssi":-42,"ch":6,"sec":"WPA2","count":377}

    {"t":"probe_req","ts":12345,"mac":"9e:1a:...","ssid":"MyHomeWifi",
     "named":true,"rssi":-61,"ch":6,"rnd":true}

    {"t":"probe_resp","ts":12345,"bssid":"aa:bb:...","ssid":"Hidden-AP",
     "rssi":-55,"ch":11,"sec":"WPA2"}

    {"t":"stat","ts":12345,"frames":48213,"queue_drops":0,
     "probe_suppressed":12,"aps":37,"heap":198432}

- `ts` — milliseconds since boot, not wall clock.
- `rssi` — dBm; for beacons, the strongest sample in the flush window.
- `ch` — from the AP's DS Parameter Set when present, which is more reliable
  than the channel we happened to receive on.
- `sec` — `OPEN`/`WEP`/`WPA`/`WPA2`/`WPA3`. WPA3 is detected by the SAE AKM
  suite in the RSN element.
- `named` — false means a wildcard probe. Most probes from modern phones are.
- `rnd` — locally-administered bit set, i.e. a randomized MAC.
- `ssid` — `<non-utf8>` marks a name that is not valid UTF-8, which would
  otherwise be indistinguishable from a hidden network.
- `queue_drops` — should stay 0; non-zero means the main loop isn't draining
  the sniffer queue fast enough.

## Channel plan

Full sweep 2.7 s: 400 ms each on 1/6/11 (where most APs live), 150 ms on the
rest. Receive only; the firmware never transmits.
