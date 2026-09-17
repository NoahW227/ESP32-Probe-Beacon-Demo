# wardrive-fw

Passive 802.11 management-frame sniffer for the ESP32. Emits newline-delimited
JSON on the USB serial console; the host program consumes it.

## Why it's built this way

**USB serial, not WiFi.** The radio can only listen to one channel at a time.
Associating to an AP to ship data over the network would pin us to that AP's
channel and kill channel hopping. Serial also means the demo doesn't depend on
conference WiFi.

**Beacons are aggregated on-device.** Every AP beacons about 10x/second. Twenty
APs in range is ~200 frames/s of near-identical data. The firmware keeps a BSSID
table and emits one row per AP per second, carrying the strongest RSSI seen in
that window plus a lifetime frame count.

**Named probe requests are never dropped.** Wildcard (empty-SSID) probes are the
overwhelming bulk of client traffic and are individually uninteresting, so they
are budgeted at 150/sec. A probe carrying an actual SSID bypasses the budget
entirely — those are rare and are the point of the demo.

## Setup (once)

    ./setup.sh          # system packages, python3.12 shim, Xtensa rust toolchain
    source env.sh       # must be sourced in every new shell before building

`setup.sh` installs python3.12 alongside the system Python. Fedora 44 ships only
Python 3.14, which ESP-IDF 5.2 does not support; the shim in `.toolchain/pybin`
puts a supported interpreter first on PATH at build time without disturbing the
system default.

## Build and flash

    source env.sh
    cargo build --release
    cargo run --release          # flashes and opens the monitor

To just watch the stream:

    espflash monitor --monitor-baud 921600

## This board

**Classic ESP32, not an ESP32-S3** — the chip identified itself as `esp32
(revision v3.1)`, WiFi+BT, 4MB flash, MAC `d4:e9:f4:89:52:90`. It enumerates as
`/dev/ttyUSB0` through a CH340/CP210x bridge. The ESP32 has no native USB
peripheral, so UART0 is the only console path.

To retarget to an actual S3 later, see the note at the top of
`.cargo/config.toml`; both toolchain targets are installed and `main.rs` needs
no changes (the promiscuous API is identical).

### Baud: 921600

    espflash monitor --monitor-baud 921600

`cargo run --release` passes this automatically.

Getting a non-default baud to stick takes more than setting it. ESP-IDF
declares the symbol as:

    prompt "UART console baud rate" if ESP_CONSOLE_UART_CUSTOM

so under the ordinary `ESP_CONSOLE_UART_DEFAULT` console choice it has **no
prompt**, is not user-settable, and any value in `sdkconfig.defaults` is
silently discarded in favour of 115200 — with no warning. `sdkconfig.defaults`
therefore selects `ESP_CONSOLE_UART_CUSTOM` and restates UART0's normal pins.
Same physical port; the only difference is that the rate now applies.

Verify it took, rather than trusting the file:

    grep CONFIG_ESP_CONSOLE_UART_BAUDRATE \
      target/xtensa-esp32-espidf/release/build/esp-idf-sys-*/out/sdkconfig

**Flashing baud is separate from console baud.** This CH340 fails flashing at
460800 (`Timeout while running ReadReg command`), so flash at the default and
leave `--baud` alone. Runtime output at 921600 is unaffected and measures 96%
clean.

Expect a few garbage bytes at the very start of each boot: the ROM bootloader
talks before the console config applies. The host skips any line not starting
with `{`, so this is cosmetic.

### Capturing a stream by hand

Serial settings revert when the last handle on the port closes, so `stty`
followed by a separate `cat` races and produces corrupt data. Hold the fd open
across both:

    exec 3<>/dev/ttyUSB0
    stty -F /dev/ttyUSB0 921600 raw -echo -echoe -echok -crtscts -ixon
    timeout 30 cat <&3 > capture.jsonl
    exec 3>&-

## Output schema (schema: 1)

One JSON object per line. Lines not starting with `{` are IDF log output and
should be skipped by the host.

    {"t":"meta","fw":"wardrive-fw 0.1","band":"2.4GHz","schema":1}

    {"t":"beacon","ts":12345,"bssid":"aa:bb:cc:dd:ee:ff","ssid":"CoffeeShop",
     "hidden":false,"rssi":-42,"ch":6,"sec":"WPA2","count":377}

    {"t":"probe_req","ts":12345,"mac":"9e:1a:...","ssid":"MyHomeWifi",
     "named":true,"rssi":-61,"ch":6,"rnd":true}

    {"t":"probe_resp","ts":12345,"bssid":"aa:bb:...","ssid":"Hidden-AP",
     "rssi":-55,"ch":11,"sec":"WPA2"}

    {"t":"stat","ts":12345,"frames":48213,"queue_drops":0,
     "probe_suppressed":12,"aps":37,"heap":198432}

Field notes:

- `ts` — milliseconds since boot, not wall clock. Host applies its own clock.
- `rssi` — dBm, higher (closer to 0) is stronger. For beacons this is the
  strongest sample in the flush window.
- `ch` — taken from the AP's DS Parameter Set tag when present, which is more
  trustworthy than the channel we happened to receive on.
- `sec` — `OPEN` / `WEP` / `WPA` / `WPA2` / `WPA3`. WPA3 is detected by the SAE
  AKM suite in the RSN element.
- `named` — false means a wildcard probe (no SSID). Expect most probes from
  modern phones to be wildcards.
- `rnd` — the locally-administered bit is set, i.e. the device is using a
  randomized MAC. This is the visible evidence of a phone trying not to be
  tracked, and is worth putting on screen.
- `hidden` — the beacon carried no SSID. A later `probe_resp` may reveal it,
  and the firmware backfills the name when that happens.
- `queue_drops` — non-zero means the main task isn't draining the callback
  queue fast enough. Should stay at 0; if it doesn't, raise the serial rate or
  tighten the probe budget.

## Channel plan

Full sweep is 2700 ms: 400 ms each on 1/6/11 (where most APs live), 150 ms on
the rest. Regulatory domain is set to manual 1–13 so the hopper can reach 12/13.
The firmware only ever receives; it never transmits.

## Measured behaviour

From a 30 s live capture on this hardware (32-34 APs in range):

    parsed=710  malformed=0
    beacon 340 | probe_resp 277 | probe_req 78 | stat 14
    queue_drops=0   heap stable across all stat lines
    throughput ~2.9 KB/s  (~3% of the 921600 link)

`malformed=0` across hundreds of records means the SSID escaping holds against
real-world names. `queue_drops=0` means the callback -> main-task handoff keeps
up. Headroom at 921600 is roughly 30x measured load, so the wildcard-probe
budget should never engage outside a very dense room.

Named probe requests do occur here at roughly 1.6/second — higher than
expected. Note they are campus SSIDs (`eduroam`, `UMASS`) rather than home
networks, and essentially all come from randomized MACs (`rnd:true`).
