"""A small curated OUI -> vendor table.

This is deliberately not the full IEEE registry: it covers the vendors likely
to show up in a room, and anything unknown falls back to displaying the OUI
prefix itself. That still redacts the device-specific half of the address, so
correctness never depends on this table being complete.
"""

OUI = {
    # Espressif (this board is d4:e9:f4)
    "24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "3c:71:bf": "Espressif",
    "7c:9e:bd": "Espressif", "84:cc:a8": "Espressif", "a4:cf:12": "Espressif",
    "b4:e6:2d": "Espressif", "c4:4f:33": "Espressif", "d4:e9:f4": "Espressif",
    # Apple
    "00:0a:95": "Apple", "00:1b:63": "Apple", "00:25:00": "Apple",
    "3c:07:54": "Apple", "40:a6:d9": "Apple", "68:a8:6d": "Apple",
    "8c:58:77": "Apple", "a4:83:e7": "Apple", "ac:bc:32": "Apple",
    "b8:e8:56": "Apple", "d0:81:7a": "Apple", "f0:18:98": "Apple",
    # Samsung
    "00:15:99": "Samsung", "08:37:3d": "Samsung", "1c:5a:3e": "Samsung",
    "34:23:ba": "Samsung", "5c:0a:5b": "Samsung", "78:47:1d": "Samsung",
    "8c:77:12": "Samsung", "bc:20:a4": "Samsung", "cc:07:ab": "Samsung",
    # Intel
    "00:1b:21": "Intel", "00:24:d7": "Intel", "34:13:e8": "Intel",
    "3c:a9:f4": "Intel", "7c:7a:91": "Intel", "94:65:9c": "Intel",
    "a0:88:69": "Intel", "e4:a4:71": "Intel",
    # HP (30:8d:99 seen locally as an Officejet)
    "00:1f:29": "HP", "30:8d:99": "HP", "3c:d9:2b": "HP",
    "70:5a:0f": "HP", "94:57:a5": "HP",
    # Google / Amazon / Roku / Sonos
    "3c:5a:b4": "Google", "54:60:09": "Google", "94:eb:2c": "Google",
    "f4:f5:d8": "Google", "44:65:0d": "Amazon", "68:37:e9": "Amazon",
    "74:c2:46": "Amazon", "f0:27:2d": "Amazon", "b0:a7:37": "Roku",
    "cc:6d:a0": "Roku", "d8:31:34": "Roku", "00:0e:58": "Sonos",
    "34:7e:5c": "Sonos", "48:a6:b8": "Sonos", "5c:aa:fd": "Sonos",
    # Microsoft / networking gear
    "00:12:5a": "Microsoft", "28:18:78": "Microsoft", "7c:1e:52": "Microsoft",
    "00:18:0a": "Cisco", "e0:cb:bc": "Cisco", "88:15:44": "Cisco",
    "04:18:d6": "Ubiquiti", "24:a4:3c": "Ubiquiti", "74:83:c2": "Ubiquiti",
    "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    "14:cc:20": "TP-Link", "50:c7:bf": "TP-Link", "60:e3:27": "TP-Link",
    "a4:2b:b0": "TP-Link", "ec:08:6b": "TP-Link",
    "00:14:6c": "Netgear", "20:4e:7f": "Netgear", "2c:30:33": "Netgear",
    "00:1b:fc": "ASUS", "2c:fd:a1": "ASUS", "38:d5:47": "ASUS",
    "50:46:5d": "ASUS", "3c:7a:8a": "Arris", "94:87:7c": "Arris",
}


def label(mac: str) -> str:
    """Redacted display form: vendor (or OUI) plus a 4-hex-char digest.

    A locally-administered address is a randomized MAC, so there is no real
    vendor to name - say so instead of implying one.
    """
    import hashlib

    parts = mac.split(":")
    if len(parts) != 6:
        return mac
    oui = ":".join(parts[:3]).lower()
    randomized = bool(int(parts[0], 16) & 0x02)
    who = "(random)" if randomized else OUI.get(oui, oui)
    tail = hashlib.sha256(mac.encode()).hexdigest()[:4]
    return f"{who}:{tail}"
