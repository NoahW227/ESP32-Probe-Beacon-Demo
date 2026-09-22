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
    **RTL88XXAU** adapters work but need out-of-tree drivers and exhibit the
    `channel -1` quirk the script already handles.
- The demo **AP**: an old router configured with **WPA-PSK / WPA2-PSK** and a
  weak passphrase. No internet uplink is required — leave the WAN port empty.
- A **client** on that network (a spare phone is ideal) to produce the handshake.

### Software (Fedora)
```bash
sudo dnf install -y aircrack-ng   # brings airmon-ng, airodump-ng, aireplay-ng
# python3 is already present on Fedora
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
| `TARGET_PASS`       | The real passphrase — used *only* for a pre-flight sanity check; never printed. |
| `MAX_DEAUTH_ROUNDS` | How many capture rounds before giving up (~5 s each; 40 ≈ 3–4 min).     |
| `AIREPLAY_OPTS`     | `--ignore-negative-one` — needed for Realtek's `channel -1` quirk; harmless otherwise. |

Find the AP's BSSID and channel by looking at the network from any device, or run
a quick `sudo airodump-ng <monitor-iface>` and read them off.

---

## 3. Run it

```bash
sudo ./wpa-demo.sh                 # auto-detect the wireless interface
sudo ./wpa-demo.sh wlp196s0f3u1    # or name the interface explicitly
```

**Root is required** (monitor mode and injection need it).

> Running this **drops your host's Wi-Fi/internet** because it stops
> NetworkManager. This is expected. Your connection is **automatically restored**
> when the script exits — by any path, including Ctrl-C or an error (see
> [§5](#5-safety-what-keeps-you-from-getting-stranded)).

### Typical live run
1. Confirm your phone is connected to the demo AP.
2. Start the script on fedora host. Curent network not important.
3. It prints progress, then reaches **CAPTURING** and tells you to force a
   handshake.
4. If injection works, it deauths the client for you. **If injection failed** (or
   to be safe), **toggle your phone's Wi-Fi OFF, wait ~3 s, turn it back ON.** The
   reconnect produces the handshake.
5. The script detects the handshake, runs the dictionary attack, and prints:
   ```
   KEY FOUND! [ larpinginacar1 ]
   ```

> 💡 **Always do one full dry run before the audience arrives.** The two things
> only a real run confirms are that your adapter captures cleanly and that the
> client emits a complete 4-way handshake on reconnect.

---

## 4. How it works, step by step

The script runs five phases. Each `==>` line in the output marks a phase.

### Phase 0 — Preflight
Checks it's running as root, that all required tools exist, and picks the wireless
interface (the argument you pass, or the first one `iw dev` reports).

### Phase 1 — Build the wordlist from the quote
This runs **first**, before touching the radio, because it's the one step that
must not fail mid-demo. An embedded Python snippet turns `QUOTE` into candidate
passphrases:

1. Lowercase the quote, drop apostrophes, split into words:
   `"It's like larping but in a car"` → `[it, s, like, larping, but, in, a, car]`.
2. Generate **every ordered sub-combination** of those words, concatenated. This
   is the key trick: the real password `larpinginacar1` isn't a contiguous slice
   of the quote (it skips "but"), but it *is* an ordered subsequence —
   `larping`+`in`+`a`+`car` — so it's guaranteed to appear as a base string.
3. For each base, add common **suffixes** (`1`, `123`, `!`, years, …) and
   **capitalization** variants (as-is, Capitalized, UPPER).
4. Write the sorted, de-duplicated list to a temp file (~5,700 candidates).

It then does a **sanity check**: `grep` confirms `TARGET_PASS` is actually in the
generated list, and warns loudly if not — so you find out *before* the radio work
if the quote wouldn't crack the password. `TARGET_PASS` is never printed.

> This mirrors a real attacker's workflow: a throwaway quote on a slide becomes a
> targeted wordlist. It's a demo shortcut, not a claim that this password would
> fall to a generic dictionary.

### Phase 2 — Monitor mode
1. Remembers whether NetworkManager was running (so it can restore it later).
2. Runs `airmon-ng check kill` to stop NetworkManager/wpa_supplicant, which
   otherwise fight for the radio. **This is what drops your Wi-Fi.**
3. **Attempt 1:** `airmon-ng start` and look for a monitor interface. Its output
   is captured so real errors are visible on failure.
4. **Attempt 2 (fallback):** if airmon-ng didn't switch the card, do it manually
   with `iw` (`down` → `set type monitor` → `up`). Some USB drivers (Realtek)
   don't cooperate with airmon-ng but work fine this way.
5. If neither worked, it dumps airmon-ng's output plus `iw dev` and exits with a
   clear message (usually: the card can't do monitor mode).

**Injection self-test:** it parks the card on `CHAN` and runs
`aireplay-ng --test` against the AP. Testing on the correct channel matters — a
blind, channel-hopping test gives false negatives. If injection works, the
automated deauth will function; if not, it prints a warning and **continues
anyway**, because the manual phone-toggle path still works.

### Phase 3 — Resolve the BSSID
Runs a ~15 s `airodump-ng` scan writing CSV, then `grep`s the CSV for `TARGET_SSID`
to read its BSSID. If the SSID isn't found (common on flaky drivers), it falls
back to `FALLBACK_BSSID`. The scan uses `timeout -k 5 15` plus a `pkill` so a
wedged airodump (a known Realtek behavior) can never hang the script forever.

### Phase 4 — Capture the handshake
1. Starts `airodump-ng` in the **background**, locked to the AP's BSSID and
   channel, writing a `.cap` (and a live `.csv`).
2. Prints the **CAPTURING** instruction reminding you to toggle the phone.
3. Loops up to `MAX_DEAUTH_ROUNDS` times. Each round:
   - `pick_client()` parses airodump's live CSV and selects the client
     **associated with the target AP that has the strongest signal** (highest PWR
     in dBm — a rough proxy for "nearest/most prominent"; it ignores clients on
     other APs and ranks "not reported" (`-1`) below real readings).
   - Sends a short `--deauth` at that client (targeted) — or a broadcast deauth if
     no client is visible yet. *(If injection doesn't work on your card, these do
     nothing; your manual phone toggle is what forces the reconnect.)*
   - Sleeps ~3 s, then checks the `.cap` with `aircrack-ng`; if it reports a
     handshake, the loop stops.
4. Kills the background airodump and moves on. If no handshake was captured in the
   allotted rounds, it exits with guidance.

> **Deauth targets by MAC, not by physical distance.** Wi-Fi can't measure range;
> "nearest" here means "strongest received signal," which in a small room with one
> phone on the network is simply that phone.

### Phase 5 — Crack
Runs `aircrack-ng -w <wordlist> -b <BSSID> <capfile>`. Because the wordlist was
built to contain the passphrase, it resolves in seconds and prints `KEY FOUND!`.
This final line **does show the recovered password** — that's the demo payoff.

---

## 5. Safety: what keeps you from getting stranded

Killing NetworkManager means a crash could leave you with no Wi-Fi. The script
guards against this:

- **`trap cleanup EXIT`** — cleanup runs on *every* exit: normal finish, error,
  `die`, or Ctrl-C. It restarts NetworkManager unconditionally, so your
  connection always comes back.
- **Idempotent cleanup** — a guard flag prevents it running twice (EXIT + signal).
- **Force-kill** — cleanup `kill -9`s the background airodump and `pkill`s any
  stray `airodump-ng`/`aireplay-ng`, so nothing keeps holding the radio.
- **`timeout -k 5`** on the scan — if airodump ignores the normal stop signal
  (Realtek quirk), it's `SIGKILL`ed 5 s later; that step can't hang forever.

If you ever do get stuck with no Wi-Fi (e.g. you killed the terminal itself):
```bash
sudo systemctl restart NetworkManager
```

All capture artifacts (the `.cap`, CSVs, wordlist) are left in a temp directory
under `/tmp/wpa-demo.XXXXXX`; the script prints the path on exit.

---

## 6. You don't strictly need injection

Handshake capture only requires **monitor mode**. The deauth step is merely an
*automated* way to make the client reconnect. If your adapter's driver can't
inject (the injection self-test warns you), you can still run the whole demo:
when it reaches **CAPTURING**, manually turn the client's Wi-Fi off and back on.
The reconnect produces the handshake and the script proceeds exactly the same.
This is the reliable fallback for temperamental Realtek adapters.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Could not enter monitor mode` | Card doesn't support monitor mode. Check `iw phy` for `* monitor`; use an AR9271 USB adapter. |
| `Injection test FAILED/inconclusive` | Often a false negative, or a driver without injection. Use the manual phone-toggle path (§6). |
| `channel -1` when testing manually | Realtek driver quirk. Add `--ignore-negative-one` (the script already does). |
| Scan finds nothing / SSID missing | Flaky driver; the script falls back to `FALLBACK_BSSID`. Make sure that's set correctly. |
| No handshake after many rounds | Client isn't reconnecting. Toggle its Wi-Fi off/on; keep it near the AP; raise `MAX_DEAUTH_ROUNDS`. |
| Handshake captured but crack fails | Incomplete handshake — force a fresh reconnect and rerun. Or the passphrase isn't in the wordlist (check the sanity-check line and `QUOTE`). |
| Realtek RTL88XXAU driver won't build | Needs `kernel-devel` matching the running kernel: `sudo dnf install -y "kernel-devel-$(uname -r)" dkms make gcc bc`; if no matching package, `sudo dnf install -y kernel kernel-devel && sudo reboot`, then rebuild. |
| No Wi-Fi after a crash | `sudo systemctl restart NetworkManager` |
