#!/usr/bin/env bash
# Figure out which ESP32-S3 board is plugged in and how its USB is wired.
# Plug the board in via micro USB, then run this.

set -uo pipefail

echo "=== serial devices ==="
found=0
for d in /dev/ttyUSB* /dev/ttyACM*; do
    [ -e "$d" ] || continue
    found=1
    echo "  $d"
    case "$d" in
      /dev/ttyACM*) echo "     -> native USB Serial/JTAG (S3 GPIO19/20 straight to the MCU)";;
      /dev/ttyUSB*) echo "     -> USB-UART bridge chip (CH340 / CP210x); console runs over UART0";;
    esac
done
[ "$found" = 0 ] && echo "  none found - is the board plugged in and the cable data-capable?"

echo
echo "=== USB descriptors ==="
lsusb 2>/dev/null | grep -Ei '303a|1a86|10c4|silicon|espressif|qinheng' || echo "  no known ESP/bridge VID seen"
echo "  (303a=Espressif native USB, 1a86=CH340, 10c4=CP210x)"

echo
echo "=== chip identity ==="
if command -v espflash >/dev/null 2>&1; then
    espflash board-info 2>&1 | sed 's/^/  /'
else
    echo "  espflash not installed yet - run ./setup.sh"
fi
