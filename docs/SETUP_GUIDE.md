# ZigBlade Setup Guide

## Day 1: T-Embed Arrives (Bruce Firmware)

### What You Need
- T-Embed CC1101 (or CC1101 Plus)
- USB-C cable
- Laptop with Chrome/Edge browser

### Flash Bruce (2 minutes, no install needed)

1. **Plug T-Embed into laptop via USB-C**

2. **Go to the web flasher:**
   ```
   https://bruce.computer/flasher
   ```

3. **Select your board:**
   - Choose "LilyGo T-Embed CC1101"
   - If you have the Plus: "LilyGo T-Embed CC1101 Plus"

4. **Click "Flash"**
   - Browser will ask to connect to serial port
   - Select the USB device (CP2102 or CH340)
   - Wait ~60 seconds

5. **Done!** T-Embed reboots into Bruce menu

### What You Can Do With Bruce

| Category | Features |
|----------|----------|
| **WiFi** | Scan, Deauth, Beacon Spam, Evil Portal, Packet Monitor |
| **BLE** | Apple BLE Spam, Samsung Spam, Android Spam, SwiftPair |
| **Sub-GHz** | Scan, Record, Replay, Brute Force, Signal Analysis |
| **IR** | TV-B-Gone, Custom IR codes, Record & Replay |
| **RFID** | Read/Write (Plus model only, PN532) |
| **BadBLE** | Wireless keyboard injection |
| **Tools** | WiFi Sniffer, Packet Capture, SD Browser |

### Test Checklist (verify all hardware works)
- [ ] Display shows Bruce menu
- [ ] Rotary encoder scrolls menu
- [ ] Encoder push selects items
- [ ] WiFi scan finds networks
- [ ] Sub-GHz scan shows signals
- [ ] BLE spam sends popups to nearby phones
- [ ] IR sends TV power off (point at any TV)
- [ ] Battery charges via USB-C
- [ ] SD card mounts (if inserted)

---

## Day 2: ESP32-H2 Arrives (ZigBlade Firmware)

### What You Need
- ESP32-H2 Waveshare DevKit
- USB-C cable
- Laptop with ESP-IDF installed (or use the VPS)

### Option A: Flash from the VPS (SSH)

```bash
# SSH into VPS
ssh root@your-vps-ip

# The firmware is already built!
cd /root/zigblade/firmware

# Plug H2 into VPS USB (or use USB-over-IP)
# If the H2 is plugged into your LOCAL laptop instead:
# Download the .bin and flash locally (see Option B)

# Flash
export IDF_PATH=/root/esp-idf
. $IDF_PATH/export.sh
idf.py -p /dev/ttyACM0 flash monitor
```

### Option B: Flash from Local Laptop

```bash
# Install ESP-IDF locally
git clone --recursive -b v5.4.1 https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32h2 && . ./export.sh

# Clone ZigBlade
git clone https://github.com/Miles0sage/zigblade.git
cd zigblade/firmware

# Build and flash
idf.py set-target esp32h2
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

### Option C: Download Pre-built Binary (Easiest)

The firmware binary is already built on the VPS:
```
/root/zigblade/firmware/build/zigblade.bin
```

Download it and flash with esptool:
```bash
pip install esptool
esptool.py --chip esp32h2 -p /dev/ttyACM0 write_flash 0x10000 zigblade.bin
```

### First Test: Standalone H2 (OLED mode)
If you have an SH1106 OLED wired up:
- Menu shows on OLED
- Navigate with buttons
- Scan Networks → see Zigbee devices around you!

### Second Test: Wire H2 to T-Embed

```
T-Embed Expansion Header    ESP32-H2 DevKit
─────────────────────────    ──────────────
GPIO43 (TX) ──────────────→ GPIO1 (RX)
GPIO44 (RX) ←────────────── GPIO0 (TX)
GND ────────────────────── GND
```

Use 3 jumper wires. That's it.

### Flash ZigBlade T-Embed Firmware

```bash
cd /root/zigblade/tembed-firmware
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

This replaces Bruce with ZigBlade UI on the T-Embed.
(You can always flash Bruce back later)

### Full System Test
1. Both devices powered
2. T-Embed shows ZigBlade main menu (color!)
3. Select "Scan Networks"
4. T-Embed sends command to H2 over UART
5. H2 scans 16 Zigbee channels
6. Results appear on T-Embed's color display
7. Select a network → start sniffing
8. Packets flow in real-time

---

## Wiring Diagram

```
    ┌─────────────────────┐
    │   LILYGO T-EMBED    │
    │   CC1101             │
    │                      │
    │   ┌──────────┐       │
    │   │  COLOR   │       │
    │   │  DISPLAY │       │
    │   │ 320x170  │       │
    │   └──────────┘       │
    │                      │
    │   [ROTARY ENCODER]   │
    │                      │
    │   GPIO43(TX)──┐      │
    │   GPIO44(RX)──┼──┐   │
    │   GND─────────┼──┼─┐ │
    └───────────────┼──┼─┼─┘
                    │  │ │
         3 jumper wires
                    │  │ │
    ┌───────────────┼──┼─┼─┐
    │   ESP32-H2    │  │ │ │
    │   WAVESHARE   │  │ │ │
    │               │  │ │ │
    │   GPIO1(RX)───┘  │ │ │
    │   GPIO0(TX)──────┘ │ │
    │   GND──────────────┘ │
    │                      │
    │   [ZIGBEE RADIO]     │
    │   802.15.4            │
    │   Channels 11-26     │
    └──────────────────────┘
```

---

## Troubleshooting

### T-Embed won't flash
- Hold BOOT button while plugging USB-C
- Try different USB-C cable (some are charge-only)
- On Mac: install CH340 driver

### H2 won't flash
- Hold BOOT button, press RESET, release BOOT
- Check serial port: `ls /dev/tty*` (look for ACM0 or USB0)

### No Zigbee networks found
- Normal in many homes! Zigbee is not as common as WiFi
- Need at least one Zigbee device (Sengled bulb, Hue, SmartThings sensor)
- Try all channels (auto-scan mode)

### UART not working between boards
- Check TX↔RX are crossed (TX of one goes to RX of other)
- Check GND is connected
- Check baud rate is 921600 in both firmwares
