# wpa-demo.sh — WPA-PSK Capture & Crack Demo

A self-contained script for a live SIGINT / packet-sniffing demonstration. It
captures a WPA/WPA2-PSK 4-way handshake from a **deliberately weak, operator-owned
access point** and cracks the passphrase offline using a wordlist derived from a
quote on the presenter's slides.

> **Scope / ethics.** This is for demonstrating against *your own* throwaway AP
> in a controlled room. Cracking Wi-Fi you don't own or have written permission to
> test is illegal in most jurisdictions. The default target (`craniel's_wifi`) is a
> disposable demo network with a password that is intentionally guessable.

---

## 1. What you need

### Hardware
- A **Wi-Fi adapter that supports monitor mode** (mandatory) and ideally packet
  injection (optional — see [§6](#6-you-dont-strictly-need-injection)).
  - Confirm monitor support: `iw phy | grep -A 12 "Supported interface modes"`
    and look for `* monitor`.
  - Built-in laptop cards often **cannot** do this. USB adapters with an Atheros
    **AR9271** (e.g. Alfa AWUS036NHA) work out of the box on Fedora. Realtek
    **RTL88XXAU** adapters (e.g. the RTL8814AU this demo was built against) work
    but need out-of-tree drivers and have quirks the script already absorbs
    (`channel -1`, an unreliable injection self-test, airodump ignoring SIGTERM).
- **Isolation mode (default) needs two radios:** the USB adapter for the attack,
  and a **separate NIC** (typically the laptop's internal card) still connected to
  a real network. This is what keeps Zoom / screen-share alive during the demo.
- The demo **AP**: an old router configured with **WPA-PSK / WPA2-PSK** and a
  weak passphrase. No internet uplink is required — leave the WAN port empty.
- A **client** on that network (a spare phone is ideal) to produce the handshake.

### Software (Fedora)
```bash
sudo dnf install -y aircrack-ng   # brings airmon-ng, airodump-ng, aireplay-ng
# python3 and nmcli are already present on a standard Fedora install
```

The script checks for `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`,
and `python3` at startup and refuses to run if any are missing.

---

## 2. Configure the script

Edit the **Config** block at the top of `wpa-demo.sh`:

| Variable            | Meaning                                                                 |
|---------------------|-------------------------------------------------------------------------|
| `TARGET_SSID`       | The network name to look for during the scan.                           |
| `FALLBACK_BSSID`    | The AP's MAC, used if the scan can't find the SSID. **Set this.**       |
| `CHAN`              | The AP's channel (fixed so the radio doesn't have to hop).              |
| `QUOTE`             | The slide quote used to seed the wordlist.                              |
| `TARGET_PASS`       | The real passphrase — used *only* for a silent pre-flight check; never printed. |
| `MAX_DEAUTH_ROUNDS` | How many capture rounds before giving up (~3 s each; 40 ≈ 3–4 min).     |
| `DEAUTH_EVERY`      | Deauth once every N rounds, then listen — so the client can reconnect **and** finish the handshake. Raise it for a longer quiet window. |
| `AIREPLAY_OPTS`     | `--ignore-negative-one` — needed for Realtek's `channel -1` quirk; harmless otherwise. |
| `ISOLATE_ADAPTER`   | `1` (default): touch only the USB adapter, leave the internal NIC (Zoom) connected. `0`: kill NetworkManager entirely (all Wi-Fi drops). |

Find the AP's BSSID and channel by looking at the network from any device, or run
a quick `sudo airodump-ng <monitor-iface>` and read them off.

---

## 3. Run it

```bash
sudo ./wpa-demo.sh                 # auto-picks the USB adapter (isolation mode)
sudo ./wpa-demo.sh wlp196s0f3u2    # or name the interface explicitly
```

**Root is required** (monitor mode and injection need it).

> **Isolation mode (default) keeps your host online.** It takes only the USB
> adapter into monitor mode and leaves your internal NIC connected, so Zoom /
> screen-share is unaffected. The adapter's interface name can change between USB
> ports (e.g. `…u1` → `…u2`); auto-detection handles that, so you normally don't
> pass an interface at all. With `ISOLATE_ADAPTER=0` the script reverts to killing
> NetworkManager, which drops **all** Wi-Fi.

### Typical live run
1. Make sure your **internal NIC is on a real network** (home Wi-Fi, hotspot,
   eduroam, …) — that carries Zoom. It must **not** be the demo AP.
2. Confirm your phone is connected to the demo AP.
3. Start the script. It auto-selects the USB adapter and never touches the
   internal NIC.
4. It prints progress, then reaches **CAPTURING**.
5. If injection works, it deauths the client for you every few seconds. **If the
   injection note says "inconclusive"** (normal on Realtek), just **toggle your
   phone's Wi-Fi OFF, wait ~3 s, turn it back ON** — the reconnect produces the
   handshake either way.
6. The script detects the handshake, runs the dictionary attack, and prints:
   ```
   KEY FOUND! [ larpinginacar1 ]
   ```

> 💡 **Always do one full dry run before the audience arrives** — with Zoom
> running, so you confirm the internal NIC stays up. The two other things only a
> real run confirms: that the adapter captures cleanly and that the client emits a
> complete 4-way handshake on reconnect.

---

## 4. How it works, step by step

Each `==>` line in the output marks a phase.

### Phase 0 — Preflight
Checks it's running as root and that all required tools exist. Then picks the
wireless interface: in isolation mode it auto-selects the **USB** adapter (by
checking whether the interface's device path is USB) and **refuses to run against
a non-USB / internal NIC**, so it can't accidentally take down your Zoom
connection. Pass an interface explicitly to override the auto-pick.

### Phase 1 — Build the wordlist from the quote
This runs **first**, before touching the radio, because it's the one step that
must not fail mid-demo. An embedded Python snippet turns `QUOTE` into candidates:

1. Lowercase the quote, drop apostrophes, split into words:
   `"It's like larping but in a car"` → `[it, s, like, larping, but, in, a, car]`.
2. Generate **every ordered sub-combination** of those words, concatenated. This
   is the key trick: the real password `larpinginacar1` isn't a contiguous slice
   of the quote (it skips "but"), but it *is* an ordered subsequence —
   `larping`+`in`+`a`+`car` — so it's guaranteed to appear as a base string.
3. For each base, add common **suffixes** (`1`, `123`, `!`, years, …) and
   **capitalization** variants (as-is, Capitalized, UPPER).
4. Write the sorted, de-duplicated list to a temp file (~5,700 candidates).

A **silent pre-flight check** then confirms `TARGET_PASS` is actually reachable in
the generated list. It prints nothing on success (so the demo doesn't look staged)
and only warns if the password *isn't* present — telling you the quote wouldn't
crack it *before* you touch the radio. `TARGET_PASS` is never printed.

> This mirrors a real attacker's workflow: a throwaway quote on a slide becomes a
> targeted wordlist. It's a demo shortcut, not a claim that this password would
> fall to a generic dictionary.

### Phase 2 — Monitor mode
**Isolation mode (default):**
1. Asks NetworkManager to release just the adapter (`nmcli device set … managed no`).
   On setups where NM never managed the USB adapter this is a harmless no-op — the
   script stays quiet about it either way.
2. Puts **only the adapter** into monitor mode via `iw`
   (`down` → `set type monitor` → `up`) and verifies the type switched.
3. The internal NIC is never touched, so the host stays online.

**Full-kill mode (`ISOLATE_ADAPTER=0`):** runs `airmon-ng check kill` (stops
NetworkManager/wpa_supplicant — this is what drops all Wi-Fi), then tries
`airmon-ng start`, falling back to the manual `iw` method if the driver doesn't
cooperate with airmon-ng (common on Realtek).

**Injection self-test:** parks the card on `CHAN` and runs `aireplay-ng --test`
against the AP (testing on the AP's channel — a blind, hopping test gives false
negatives). It reports the result as a **single neutral line**. On the Realtek
adapter this test is unreliable and often says "inconclusive" even when deauth
actually works, so it never blocks: the run always continues, and the manual
phone-toggle path is the fallback.

### Phase 3 — Resolve the BSSID
Runs a ~15 s `airodump-ng` scan to CSV, then `grep`s it for `TARGET_SSID` to read
the BSSID. If not found (common on flaky drivers), it falls back to
`FALLBACK_BSSID`. The scan uses `timeout -k 5 15` so a wedged airodump (it ignores
SIGTERM on Realtek and is `SIGKILL`ed 5 s later) can't hang the script; the scan
is backgrounded and `wait`ed on so the shell's "Killed" notice never reaches the
demo output.

### Phase 4 — Capture the handshake
1. Starts `airodump-ng` in the **background**, locked to the AP's BSSID and
   channel, writing a `.cap` (and a live `.csv`).
2. Prints the **CAPTURING** instruction.
3. Loops up to `MAX_DEAUTH_ROUNDS` times. It **deauths only once every
   `DEAUTH_EVERY` rounds, then listens** for the remaining rounds. This is
   essential: continuous deauth keeps kicking the client off before it can
   complete the 4-way handshake — the burst-then-listen rhythm gives it a window
   to reconnect *and* finish. On a deauth round:
   - `pick_client()` parses airodump's live CSV and selects the client
     **associated with the target AP that has the strongest signal** (highest PWR
     in dBm — a proxy for "nearest/most prominent"; it ignores clients on other
     APs and ranks "not reported" (`-1`) below real readings).
   - Sends a short `--deauth` burst at that client (targeted), or a broadcast
     deauth if no client is visible yet. *(If the card can't inject, these do
     nothing and your manual phone toggle forces the reconnect instead.)*
   - Listening rounds just sleep ~3 s and re-check.
   - Each round checks the `.cap` with `aircrack-ng`; a detected handshake stops
     the loop.
4. Force-kills the background airodump and moves on. If no handshake was captured
   in the allotted rounds, it exits with guidance.

> **Deauth targets by MAC, not by physical distance.** Wi-Fi can't measure range;
> "nearest" here means "strongest received signal," which in a small room with one
> phone on the network is simply that phone.

### Phase 5 — Crack
Runs `aircrack-ng -w <wordlist> -b <BSSID> <capfile>`. Because the wordlist was
built to contain the passphrase, it resolves in seconds and prints `KEY FOUND!`.
This final line **does show the recovered password** — that's the demo payoff.

---

## 5. Safety: what keeps you from getting stranded

Touching the radio could otherwise leave you offline. The script guards this:

- **`trap cleanup EXIT`** — cleanup runs on *every* exit: normal finish, error,
  `die`, or Ctrl-C.
- **Isolation-aware restore** — in isolation mode cleanup returns **only the
  adapter** to managed mode and hands it back to NetworkManager; it does this by
  *mode*, so it works even when the earlier unmanage step reported "not found."
  The internal NIC (Zoom) is never disturbed. In full-kill mode it restarts
  NetworkManager instead.
- **Idempotent cleanup** — a guard flag prevents it running twice (EXIT + signal).
- **Force-kill** — cleanup `kill -9`s the background airodump and `pkill`s any
  stray `airodump-ng`/`aireplay-ng`, so nothing keeps holding the radio.
- **`timeout -k 5`** on the scan — a wedged airodump is `SIGKILL`ed rather than
  hanging the run forever.

If you ever do get stuck with no Wi-Fi (e.g. you killed the terminal itself):
```bash
# return the adapter to normal:
sudo ip link set <adapter> down && sudo iw dev <adapter> set type managed && sudo ip link set <adapter> up
# or, in full-kill mode:
sudo systemctl restart NetworkManager
```

All capture artifacts (the `.cap`, CSVs, wordlist) are left in a temp directory
under `/tmp/wpa-demo.XXXXXX`; the script prints the path on exit.

---

## 6. You don't strictly need injection

Handshake capture only requires **monitor mode**. The deauth step is merely an
*automated* way to make the client reconnect. If your adapter can't inject (or the
self-test is inconclusive, as it usually is on Realtek), you can still run the
whole demo: when it reaches **CAPTURING**, manually turn the client's Wi-Fi off
and back on. The reconnect produces the handshake and the script proceeds exactly
the same. This is the reliable fallback for temperamental Realtek adapters.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `is not a USB adapter` / refuses to run | Isolation mode won't attack a non-USB (likely internal) NIC. Pass the USB adapter's name, or set `ISOLATE_ADAPTER=0` to override. |
| `No USB wireless adapter found` | Adapter not plugged in or not recognized. Check `iw dev`; pass the interface explicitly. |
| `Could not put … into monitor mode` | Card doesn't support monitor mode. Check `iw phy` for `* monitor`; use an AR9271 USB adapter. |
| Injection note says "inconclusive" | Expected on Realtek — often a false negative. Not a failure; use the manual phone-toggle path (§6) if automated deauth doesn't land. |
| `channel -1` when testing manually | Realtek driver quirk. Add `--ignore-negative-one` (the script already does). |
| Scan finds nothing / SSID missing | Flaky driver; the script falls back to `FALLBACK_BSSID`. Make sure that's set correctly. |
| Client keeps getting kicked, no handshake | Deauth too aggressive — raise `DEAUTH_EVERY` for a longer listen window. |
| No handshake after many rounds | Client isn't reconnecting. Toggle its Wi-Fi off/on; keep it near the AP; raise `MAX_DEAUTH_ROUNDS`. |
| Handshake captured but crack fails | Incomplete handshake — force a fresh reconnect and rerun. Or the passphrase isn't in the wordlist (check `QUOTE` / `TARGET_PASS`). |
| Realtek RTL88XXAU driver won't build | Needs `kernel-devel` matching the running kernel: `sudo dnf install -y "kernel-devel-$(uname -r)" dkms make gcc bc`; if no matching package, `sudo dnf install -y kernel kernel-devel && sudo reboot`, then rebuild. |
| Lost Wi-Fi after a crash | Restore the adapter (`iw … set type managed`) or `sudo systemctl restart NetworkManager` — see §5. |
