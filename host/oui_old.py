"""MAC address -> display label.

Two things are being distinguished, and it is worth keeping them straight:

* Whether the address is *randomized*. A locally-administered address (bit 1
  of the first octet) is invented by the device to resist tracking, so there
  is no manufacturer behind it to name.
* Who made the device, for real hardware addresses. That comes from the first
  three octets, the OUI, which IEEE assigns to a manufacturer.

The vendor table is the system IEEE registry (hwdata, ~40k entries) when it is
present, falling back to a small built-in list otherwise. Anything still
unresolved shows the bare OUI - the device-specific half stays hidden either
way, so redaction never depends on the lookup succeeding.
"""

import hashlib
import re

SYSTEM_DBS = (
    "/usr/share/hwdata/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
)

# Used only if no system registry is installed.
FALLBACK = {
    "d4:e9:f4": "Espressif", "24:0a:c4": "Espressif", "a4:cf:12": "Espressif",
    "00:0a:95": "Apple", "a4:83:e7": "Apple", "ac:bc:32": "Apple",
    "08:37:3d": "Samsung", "34:23:ba": "Samsung", "cc:07:ab": "Samsung",
    "3c:a9:f4": "Intel", "94:65:9c": "Intel", "e4:a4:71": "Intel",
    "30:8d:99": "HP", "3c:d9:2b": "HP", "b0:a7:37": "Roku",
    "3c:5a:b4": "Google", "44:65:0d": "Amazon", "00:0e:58": "Sonos",
}

# Legal boilerplate that adds nothing on a projector.
_NOISE = re.compile(
    r"\b(inc|inc\.|incorporated|corp|corp\.|corporate|corporation|co|co\.|company|"
    r"ltd|ltd\.|limited|llc|l\.l\.c\.|gmbh|ag|a/s|b\.v\.|s\.a\.|s\.p\.a\.|plc|"
    r"technologies|technology|electronics|electronic|communications|computer|"
    r"international|holdings|group|industrial|systems)\b",
    re.I,
)


def _shorten(name: str, cap: int = 16) -> str:
    name = _NOISE.sub("", name)
    name = re.sub(r"[,&]", " ", name)
    name = " ".join(name.split()).strip(" .-")
    if len(name) > cap:                 # still long: the first word carries it
        name = name.split(" ")[0][:cap]
    return name or "unknown"


def _load():
    for path in SYSTEM_DBS:
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        table = {}
        with fh:
            for line in fh:
                m = re.match(
                    r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$",
                    line,
                )
                if m:
                    key = f"{m.group(1)}:{m.group(2)}:{m.group(3)}".lower()
                    table[key] = _shorten(m.group(4))
        if table:
            return table, path
    return {k: _shorten(v) for k, v in FALLBACK.items()}, "built-in"


OUI, SOURCE = _load()


def describe(mac: str):
    """Return (display_label, kind).

    kind is 'random' for a randomized address, 'vendor' when the manufacturer
    resolved, and 'unknown' when it did not - so the page can show an
    unresolved vendor as a gap in the lookup rather than a third category of
    address.
    """
    parts = mac.split(":")
    if len(parts) != 6:
        return mac, "unknown"
    tail = hashlib.sha256(mac.encode()).hexdigest()[:4]

    if int(parts[0], 16) & 0x02:        # locally administered == randomized
        return f"(random):{tail}", "random"

    oui = ":".join(parts[:3]).lower()
    vendor = OUI.get(oui)
    if vendor:
        return f"{vendor}:{tail}", "vendor"
    return f"{oui}:{tail}", "unknown"


def label(mac: str) -> str:
    return describe(mac)[0]
