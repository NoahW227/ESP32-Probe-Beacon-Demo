#!/usr/bin/env python3
"""Live display for the ESP32 wardriving sniffer.

Reads newline-delimited JSON from the board (or from a recorded capture) and
serves a browser page over Server-Sent Events.

    ./host/host.py                                   # live from /dev/ttyUSB0
    ./host/host.py --replay captures/demo-fallback.jsonl
    ./host/host.py --watch "Smith Family WiFi"       # pin an SSID when seen

Standard library only - no pip, no sudo. We never write to the serial port, so
after setting the line discipline with termios it reads as a plain file.
"""

import argparse
import json
import os
import sys
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oui import SOURCE as OUI_SOURCE, describe as mac_describe, label as mac_label

HERE = os.path.dirname(os.path.abspath(__file__))

# How many rows each column shows. The store keeps everything; this is display.
ROWS = 15
# Distinct (MAC, SSID) pairs retained. One scanning device can emit many frames
# per second, so the feed is keyed rather than appended.
PROBE_KEEP = 600
# Drop a pair we have not heard from in this long, so the feed stays current.
PROBE_STALE_S = 180
SNAPSHOT_HZ = 2


# --- serial -----------------------------------------------------------------

def open_serial(path, baud):
    """Open the port raw at `baud`.

    The fd is held for the process lifetime: line settings revert when the last
    handle closes, so setting them and reopening separately would race.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOCTTY)
    try:
        speed = getattr(termios, f"B{baud}")
    except AttributeError:
        raise SystemExit(f"unsupported baud rate: {baud}")

    iflag, oflag, cflag, lflag, _, _, cc = termios.tcgetattr(fd)
    iflag = 0                                    # no translation, no flow control
    oflag = 0
    cflag = termios.CS8 | termios.CREAD | termios.CLOCAL
    lflag = 0                                    # raw: no echo, no canonical mode
    cc = list(cc)
    cc[termios.VMIN] = 1
    cc[termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, [iflag, oflag, cflag, lflag, speed, speed, cc])
    return os.fdopen(fd, "rb", buffering=0)


# --- state ------------------------------------------------------------------

class Store:
    """Everything the board has told us, plus the derived view the page needs."""

    def __init__(self, watch=()):
        self.lock = threading.Lock()
        self.aps = {}                 # bssid -> latest beacon record
        self.probes = {}              # (mac, ssid) -> one row, not one per frame
        self.named = {}               # ssid -> aggregate of named probe requests
        self.devices = set()          # every probing MAC ever seen
        self.watch = {w.lower() for w in watch}
        self.stat = {}
        self.frames_per_sec = 0.0
        self._last_frames = None
        self._last_ts = None
        self.started = time.time()
        self.last_rx = 0.0

    def ingest(self, rec):
        kind = rec.get("t")
        with self.lock:
            self.last_rx = time.time()
            if kind == "beacon":
                self.aps[rec["bssid"]] = rec
            elif kind == "probe_req":
                self.devices.add(rec["mac"])
                self._add_probe(rec)
                if rec.get("named") and rec.get("ssid"):
                    self._add_named(rec)
            elif kind == "probe_resp":
                # Fills in a cloaked AP's name when the beacon carried none.
                ap = self.aps.get(rec["bssid"])
                if ap and ap.get("hidden") and rec.get("ssid"):
                    ap["ssid"] = rec["ssid"]
                    ap["hidden"] = False
            elif kind == "stat":
                self._update_rate(rec)
                self.stat = rec

    def _add_probe(self, rec):
        """Collapse to one row per (MAC, SSID).

        A device scanning the band emits the same wildcard probe many times a
        second. Appending each one lets a single device occupy every visible
        row and push out the rare named probes that matter.
        """
        mac, ssid = rec["mac"], rec.get("ssid", "")
        now = time.time()
        e = self.probes.get((mac, ssid))
        if e is None:
            lab, kind = mac_describe(mac)
            e = {
                "mac": mac, "label": lab, "kind": kind, "ssid": ssid,
                "named": bool(rec.get("named")), "rnd": bool(rec.get("rnd")),
                "count": 0, "rssi": -127,
            }
            self.probes[(mac, ssid)] = e
        e["count"] += 1
        # Strongest sample, not the latest: a live-updating value jitters by a
        # few dB every frame, which reads as noise on a projector.
        e["rssi"] = max(e["rssi"], rec["rssi"])
        e["ch"] = rec["ch"]
        e["last"] = now

        if len(self.probes) > PROBE_KEEP:
            cutoff = now - PROBE_STALE_S
            self.probes = {
                k: v for k, v in self.probes.items() if v["last"] >= cutoff
            }
            if len(self.probes) > PROBE_KEEP:   # still over: drop oldest
                keep = sorted(self.probes.items(), key=lambda kv: -kv[1]["last"])
                self.probes = dict(keep[:PROBE_KEEP])

    def _add_named(self, rec):
        e = self.named.setdefault(
            rec["ssid"],
            {"ssid": rec["ssid"], "count": 0, "best_rssi": -127, "devices": set(),
             "watched": rec["ssid"].lower() in self.watch},
        )
        e["count"] += 1
        e["best_rssi"] = max(e["best_rssi"], rec["rssi"])
        e["devices"].add(rec["mac"])
        e["last"] = time.time()

    def _update_rate(self, rec):
        """Frames/sec from the firmware's own counter, which also counts frames
        that were budget-suppressed and never sent."""
        f, ts = rec.get("frames"), rec.get("ts")
        if self._last_frames is not None and ts > self._last_ts:
            self.frames_per_sec = (f - self._last_frames) * 1000.0 / (ts - self._last_ts)
        self._last_frames, self._last_ts = f, ts

    def snapshot(self, mode):
        with self.lock:
            # Beacons by signal strength: the closest AP is the room's own, and
            # belongs at the top. Frequency would be useless here - every AP
            # beacons at the same rate, so counts just track uptime.
            beacons = sorted(self.aps.values(), key=lambda a: -a["rssi"])[:ROWS]
            beacons = [dict(b, label=mac_label(b["bssid"])) for b in beacons]

            # One row per (MAC, SSID), most recently heard first. Deliberately
            # not ranked named-first: the wildcard traffic is most of what is
            # in the air and showing it is the point. Named probes persist in
            # the leaked-networks panel regardless, so nothing is lost here.
            feed = sorted(self.probes.values(), key=lambda e: -e["last"])[:ROWS]
            feed = [
                {k: e[k] for k in ("mac", "label", "kind", "ssid", "named", "rssi", "ch", "rnd", "count")}
                for e in feed
            ]

            named = sorted(
                self.named.values(),
                key=lambda e: (not e["watched"], -e["count"]),
            )[:ROWS]
            named = [
                {"ssid": e["ssid"], "count": e["count"], "best_rssi": e["best_rssi"],
                 "devices": len(e["devices"]), "watched": e["watched"]}
                for e in named
            ]

            stale = time.time() - self.last_rx if self.last_rx else 999
            return {
                "mode": mode,
                "stale": stale > 5,
                "beacons": beacons,
                "probes": feed,
                "named": named,
                "counters": {
                    "aps": len(self.aps),
                    "devices": len(self.devices),
                    "named_ssids": len(self.named),
                    "fps": round(self.frames_per_sec, 1),
                    "drops": self.stat.get("queue_drops", 0),
                    "suppressed": self.stat.get("probe_suppressed", 0),
                    "heap": self.stat.get("heap", 0),
                    "uptime": int(time.time() - self.started),
                },
            }


# --- input sources ----------------------------------------------------------

def pump_serial(stream, store):
    for raw in iter(stream.readline, b""):
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("{"):
            continue          # ROM bootloader chatter shares the wire
        try:
            store.ingest(json.loads(line))
        except json.JSONDecodeError:
            pass


def pump_replay(path, store, loop=True):
    """Replay a capture at its original pace so it looks live on stage."""
    with open(path) as fh:
        records = [json.loads(l) for l in fh if l.strip().startswith("{")]
    if not records:
        raise SystemExit(f"{path}: no JSON records")

    while True:
        prev = None
        for rec in records:
            ts = rec.get("ts")
            if prev is not None and ts is not None:
                # Cap the gap so a pause in the recording isn't a dead screen.
                time.sleep(min(max((ts - prev) / 1000.0, 0), 2.0))
            if ts is not None:
                prev = ts
            store.ingest(rec)
        if not loop:
            return
        store.__init__(watch=store.watch)   # clear between loops


# --- http -------------------------------------------------------------------

def make_handler(store, mode):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass                      # keep the console clean during a talk

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._file("index.html", "text/html; charset=utf-8")
            elif self.path == "/events":
                self._events()
            elif self.path == "/state":
                self._json(store.snapshot(mode))
            else:
                self.send_error(404)

        def _file(self, name, ctype):
            try:
                body = open(os.path.join(HERE, name), "rb").read()
            except OSError:
                return self.send_error(404)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _events(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                while True:
                    payload = json.dumps(store.snapshot(mode))
                    self.wfile.write(f"data: {payload}\n\n".encode())
                    self.wfile.flush()
                    time.sleep(1.0 / SNAPSHOT_HZ)
            except (BrokenPipeError, ConnectionResetError):
                pass              # browser tab closed

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Wardriving display host")
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--replay", metavar="FILE", help="replay a capture instead of reading serial")
    ap.add_argument("--http-port", type=int, default=8000)
    ap.add_argument("--watch", action="append", default=[],
                    help="pin this SSID to the top when seen (repeatable)")
    args = ap.parse_args()

    store = Store(watch=args.watch)
    mode = "replay" if args.replay else "live"

    if args.replay:
        src = threading.Thread(target=pump_replay, args=(args.replay, store), daemon=True)
    else:
        if not os.path.exists(args.port):
            raise SystemExit(f"{args.port} not found - is the board plugged in?")
        stream = open_serial(args.port, args.baud)
        src = threading.Thread(target=pump_serial, args=(stream, store), daemon=True)
    src.start()

    srv = ThreadingHTTPServer(("127.0.0.1", args.http_port), make_handler(store, mode))
    url = f"http://127.0.0.1:{args.http_port}/"
    src_desc = args.replay if args.replay else f"{args.port} @ {args.baud}"
    print(f"  source : {src_desc}  ({mode})")
    print(f"  display: {url}")
    print("  press M in the browser to reveal full MACs, +/- to resize")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
