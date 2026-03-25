# ZigBlade Ultimate — Hardware BOM

> Kill Flipper Zero, Kode Dot, and POOM in one device.

## Design Philosophy
- ESP32-H2 for 802.15.4 (Zigbee/Thread/Matter) — **what nobody else has**
- ESP32-C5 for WiFi 2.4/5GHz + BLE — **dual-band like POOM**
- CC1101 for Sub-GHz — **like Flipper Zero**
- NFC + 125kHz RFID — **like Kode Dot**
- AMOLED color display — **better than Flipper's monochrome**
- Custom 3D printed enclosure — **outer-world aesthetic**

---

## Tier 1: MVP Prototype ($35-45)
*Get something working NOW on a breadboard*

| # | Part | Model | Price | Source |
|---|------|-------|-------|--------|
| 1 | Main MCU | ESP32-H2-DevKitM-1 (N4) | $10 | Mouser/DigiKey |
| 2 | Display | 1.3" SH1106 OLED I2C 128x64 | $5 | AliExpress |
| 3 | Battery | 3.7V 1000mAh LiPo (JST-PH 2.0) | $5 | AliExpress |
| 4 | Charger | TP4056 USB-C with DW01 protection | $1.50 | AliExpress |
| 5 | Buttons | 4x 6mm tactile switches | $0.50 | AliExpress |
| 6 | SD Card | MicroSD SPI breakout + 8GB card | $5 | AliExpress |
| 7 | LED | WS2812B 5050 RGB x1 | $0.50 | AliExpress |
| 8 | Proto | Half-size breadboard + jumpers | $3 | Local |
| | | **TOTAL** | **~$31** | |

---

## Tier 2: Feature Complete ($75-100)
*Match Flipper + Kode Dot + POOM all-in-one*

| # | Part | Model | Price | Why |
|---|------|-------|-------|-----|
| 1 | **Zigbee/Thread/Matter MCU** | ESP32-H2-MINI-1U (IPEX) | $4 | 802.15.4 radio — THE killer feature |
| 2 | **WiFi/BLE MCU** | ESP32-C5 module (dual-band) | $5 | 2.4+5GHz WiFi + BLE 5.x |
| 3 | **Sub-GHz Radio** | CC1101 module (SPI) | $3 | 315/433/868/915 MHz — garage, remotes |
| 4 | **NFC/RFID HF** | PN532 module (I2C/SPI) | $4 | 13.56MHz — Mifare, NTAG, badges |
| 5 | **RFID LF** | EM4100 reader module (125kHz) | $3 | Low-freq access cards |
| 6 | **IR TX/RX** | IR LED + TSOP38238 receiver | $1 | TV/AC control — like Flipper |
| 7 | **Display** | 1.69" ST7789 IPS TFT 240x280 (color!) | $6 | Color > Flipper's monochrome |
| 8 | **Battery** | 3.7V 2000mAh LiPo flat pack | $7 | All-day battery life |
| 9 | **PMIC** | IP5306 boost+charge (USB-C) | $2 | Proper power management |
| 10 | **Antenna (802.15.4)** | 2.4GHz 5dBi u.FL pigtail | $2 | Extended Zigbee range |
| 11 | **Antenna (Sub-GHz)** | 433MHz spring antenna | $1 | Extended Sub-GHz range |
| 12 | **SD Card** | MicroSD slot (SDMMC) | $1 | PCAP storage, payloads |
| 13 | **Buttons** | 5-way joystick + 2 side buttons | $3 | Proper navigation |
| 14 | **Speaker** | 8ohm 1W micro speaker | $1 | Audio feedback |
| 15 | **Mic** | INMP441 I2S MEMS mic | $2 | Voice commands (future AI) |
| 16 | **USB-C** | Connector + ESD + JTAG debug | $1 | Data + charge + debug |
| 17 | **LED** | WS2812B NeoPixel x2 | $0.50 | Status indicators |
| 18 | **Vibration** | Coin vibration motor | $0.50 | Haptic feedback |
| | | **TOTAL** | **~$47 per unit** | |

Plus PCB + 3D case:
- Custom 4-layer PCB (JLCPCB, 50 units): ~$3/board
- 3D printed case (SLA resin for smooth finish): ~$5/unit
- **TOTAL PER UNIT: ~$55-60**
- **SELL PRICE: $119-149** (60-65% margin)

---

## Tier 3: Pro Edition ($100-130)
*For serious pentesters who want maximum range and features*

Add to Tier 2:
| # | Part | Model | Price | Why |
|---|------|-------|-------|-----|
| 1 | **HackRF Frontend** | nRF24L01+PA/LNA | $4 | Proprietary 2.4GHz (mice, keyboards) |
| 2 | **GPS** | NEO-6M GPS module | $5 | Wardriving + geolocation |
| 3 | **Display upgrade** | 2.0" IPS 320x240 (ILI9341) | $8 | Larger, touch optional |
| 4 | **Battery upgrade** | 3.7V 3000mAh LiPo | $10 | 8+ hours active use |
| 5 | **External antenna SMA** | SMA connector + pigtail | $2 | Swap antennas per protocol |
| 6 | **Qwiic** | Qwiic/I2C expansion port | $1 | 100+ sensors/modules |
| | | **TOTAL ADDITION** | **~$30** | |
| | | **TOTAL PRO** | **~$85-90/unit** | |
| | | **SELL PRICE** | **$179-199** | Beats Flipper at $169 with MORE features |

---

## Feature Kill Chart — What Beats What

| Feature | Flipper $169 | Kode Dot $129 | POOM ~$80 | ZigBlade $119 |
|---------|:---:|:---:|:---:|:---:|
| **Zigbee attacks** | -- | -- | sniff only | **INJECT + REPLAY** |
| **Thread/Matter** | -- | -- | sniff only | **FULL ATTACKS** |
| **WiFi 2.4GHz** | add-on $30 | via module | built-in | built-in (C5) |
| **WiFi 5GHz** | -- | via module | built-in | built-in (C5) |
| **BLE** | yes | yes | yes | yes (C5) |
| **Sub-GHz** | yes (CC1101) | via module | -- | yes (CC1101) |
| **NFC 13.56MHz** | yes | yes | yes (PN532) | yes (PN532) |
| **RFID 125kHz** | yes | yes | -- | yes (EM4100) |
| **IR TX/RX** | yes | yes | -- | yes |
| **BadUSB** | yes | yes | yes | yes (C5 USB) |
| **Color display** | no (mono) | yes (AMOLED) | no (OLED) | **yes (IPS TFT)** |
| **AI/Voice** | -- | yes (GPT) | -- | **future (mic+WiFi)** |
| **GPS wardriving** | -- | -- | -- | **yes (Pro)** |
| **Battery** | 2000mAh | 500mAh | ~1000mAh | 2000-3000mAh |
| **Open source** | FW only | CC BY-NC-ND | yes | **MIT (everything)** |
| **Custom PCB** | yes | yes | yes | yes (KiCad) |
| **Price** | $169 | $129+module | ~$80 | **$119 base** |

### ZigBlade wins on:
1. **Only device with Zigbee/Thread/Matter ATTACKS** (not just sniffing)
2. **All protocols in one** (no modules needed like Kode Dot)
3. **Color display** (beats Flipper's monochrome)
4. **MIT license** (fork it, sell it, modify it — no restrictions)
5. **Cheaper** than Flipper with more features
6. **GPS wardriving** (Pro edition) — nobody else has this

### What Kode Dot has that we should match:
- [x] AMOLED display (we use IPS TFT — cheaper but still color)
- [x] Voice I/O (we have mic + speaker hardware)
- [x] App system (kodeOS) — we can build a menu-based app launcher
- [ ] Magnetic pogo connector (nice-to-have, not essential)
- [ ] 9-axis IMU (not needed for security tool)

### What Flipper has that we should match:
- [x] Sub-GHz (CC1101 ✓)
- [x] NFC/RFID (PN532 + EM4100 ✓)
- [x] IR (LED + TSOP ✓)
- [x] BadUSB (ESP32-C5 USB HID ✓)
- [x] GPIO (expansion header ✓)
- [ ] iButton (niche, skip)
- [ ] Dolphin pet UI (we can do better — Pwnagotchi-style AI personality)

---

## 3D Enclosure Design Notes

For your custom 3D printed enclosure:

### Dimensions (target)
- Width: 70mm (pocket-friendly)
- Height: 45mm
- Depth: 18mm (with battery)
- Weight: ~80g

### Design Ideas for "Outer World" Aesthetic
- **Translucent resin** (SLA print) — see the PCB through the case
- **Cyberpunk hex pattern** — honeycomb ventilation that looks aggressive
- **Edge-lit LED ring** — WS2812B strip around the perimeter, visible through translucent case
- **Blade-shaped profile** — thin wedge, thicker at battery end, tapers to antenna
- **Magnetic snap back** — 4x magnets for tool-free battery swap / module access
- **Belt clip / lanyard loop** — field-ready
- **Color accent** — matte black body with neon green or red transparent accent strips

### Recommended Print
- **Material**: Clear/smoke resin (Elegoo/Anycubic SLA) for main body
- **Accents**: TPU (flexible) for grip strips, button caps
- **Finish**: UV-cured clear coat for durability + gloss
- **Internal**: PETG for structural elements (battery tray, PCB mounts)

### Tools
- **3D design**: Fusion 360 (free for personal) or FreeCAD
- **STL export** → JLCPCB 3D printing or own printer
- **Tolerance**: 0.2mm clearance on all edges for SLA

---

## Shopping List — Order NOW

### Amazon/Mouser (Fast Shipping)
1. ESP32-H2-DevKitM-1 — [Mouser: $9.90](https://www.mouser.com)
2. Philips Hue Starter Kit (test target) — Amazon ~$50

### AliExpress (Bulk + Cheap, 2-3 week shipping)
1. ESP32-C5 dev board — ~$5
2. CC1101 SPI module — ~$3
3. PN532 NFC module — ~$4
4. EM4100 125kHz reader — ~$3
5. 1.69" ST7789 TFT IPS 240x280 — ~$6
6. INMP441 I2S MEMS microphone — ~$2
7. 3.7V 2000mAh LiPo flat — ~$7
8. IP5306 USB-C charge+boost board — ~$2
9. 5-way joystick module — ~$2
10. IR LED + TSOP38238 — ~$1
11. WS2812B NeoPixel strip (8 LEDs) — ~$1
12. MicroSD slot breakout — ~$1
13. SMA to u.FL pigtail — ~$1
14. 2.4GHz 5dBi antenna (u.FL) — ~$2
15. 433MHz spring antenna — ~$1

**Total AliExpress order: ~$41**
**Total with Mouser ESP32-H2: ~$51**
**Total with test target: ~$101**
