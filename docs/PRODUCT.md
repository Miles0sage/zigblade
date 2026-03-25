<p align="center">
  <img src="../assets/zigblade-logo.png" alt="ZigBlade" width="200"/>
</p>

<h1 align="center">ZigBlade</h1>

<p align="center">
  <b>The first pocket-sized offensive security tool for Zigbee, Thread, and Matter.</b>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#comparison">Comparison</a> &bull;
  <a href="#specs">Specs</a> &bull;
  <a href="#use-cases">Use Cases</a> &bull;
  <a href="#hardware">Hardware</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#roadmap">Roadmap</a> &bull;
  <a href="#license">License</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"/>
  <img src="https://img.shields.io/badge/firmware-5%2C595_lines-blue" alt="Firmware Lines"/>
  <img src="https://img.shields.io/badge/cost-%2430--50-orange" alt="Hardware Cost"/>
  <img src="https://img.shields.io/badge/ESP--IDF-v5.4.1-red" alt="ESP-IDF"/>
</p>

---

Smart locks. Smart homes. Smart factories. **None of them have been properly tested.**

802.15.4-based protocols (Zigbee, Thread, Matter) now control billions of devices -- door locks, industrial sensors, HVAC systems, medical equipment. Yet the security tooling for these protocols is either passive-only, costs thousands, or requires dragging a laptop into the field.

ZigBlade changes that. Built on the ESP32-H2, it fits in your pocket, runs on a battery, and does what no other portable tool can: **active offensive testing** -- injection, replay, fuzzing, impersonation -- alongside passive analysis. All for under $50 in parts.

Open source. MIT licensed. No subscriptions. No vendor lock-in.

---

## Features

### Passive Analysis
- **16-channel scanner** -- sweep all 802.15.4 channels, identify active networks
- **Live packet sniffing** -- real-time decode displayed on 128x64 OLED
- **Auto key extraction** -- capture encryption keys during pairing via the ZigBeeAlliance09 well-known key vulnerability
- **PCAP export** -- Wireshark-compatible captures to SD card

### Active Attacks
- **Raw packet injection** -- craft and send arbitrary 802.15.4 frames
- **Replay attacks** -- capture and retransmit packets
- **Beacon flooding** -- overwhelm networks with spoofed beacons
- **Disassociation attacks** -- force devices off their network
- **Touchlink commissioning** -- exploit Zigbee Light Link factory reset vulnerability
- **Coordinator impersonation** -- pose as the network coordinator
- **ZCL command fuzzing** -- automated malformed-command testing against Zigbee Cluster Library endpoints

### Protocol Coverage
- **Zigbee 3.0** -- full attack surface
- **Thread 1.3** -- network discovery and analysis
- **Matter 1.0+** -- session-level testing

### Hardware Crypto
- **AES-128 CCM*** -- hardware-accelerated encryption/decryption via ESP32-H2's built-in crypto engine. No software overhead, no speed penalty.

---

<a id="comparison"></a>
## How ZigBlade Compares

| | **ZigBlade** | **POOM** | **KillerBee + ApiMote** | **Flipper Zero** | **Kode Dot** | **Ubiqua** | **Ellisys** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Price** | **$30-50** | ~$80 | $150+ | $169 | $129-169 | $650/yr | $50,000+ |
| **Portable** | Yes | Yes | No (laptop) | Yes | Yes | No (software) | No (rack) |
| **802.15.4 (Zigbee)** | Yes | Yes | Yes | No | No | Yes | Yes |
| **Thread** | Yes | Partial | No | No | No | Partial | Yes |
| **Matter** | Yes | No | No | No | No | No | Partial |
| **Passive sniffing** | Yes | Yes | Yes | -- | -- | Yes | Yes |
| **Packet injection** | **Yes** | No | Yes | -- | -- | No | No |
| **Replay attacks** | **Yes** | No | Limited | -- | -- | No | No |
| **Key extraction** | **Yes** | Manual | Yes | -- | -- | No | No |
| **Fuzzing** | **Yes** | No | Limited | -- | -- | No | No |
| **Coordinator impersonation** | **Yes** | No | No | -- | -- | No | No |
| **Touchlink attacks** | **Yes** | No | No | -- | -- | No | No |
| **OLED display** | Yes | Yes | No | Yes | No | -- | -- |
| **Battery powered** | Yes | Yes | No | Yes | Yes | -- | -- |
| **Open source** | **MIT** | Pending | GPL | GPL | CC BY-NC-ND | Proprietary | Proprietary |
| **Maintained** | **Active** | Pre-release | Abandoned (2023) | Active | Active | Active | Active |
| **Python 3 / modern stack** | ESP-IDF 5.4 (C) | ESP-IDF (C) | Python 2.7 | C | Arduino | C#/.NET | Proprietary |

**TL;DR:** POOM can sniff. KillerBee can inject but needs a laptop and Python 2.7. Flipper Zero doesn't do 802.15.4 at all. ZigBlade is the only portable tool that does both passive and active testing across Zigbee, Thread, and Matter.

---

<a id="specs"></a>
## Technical Specifications

| Spec | Detail |
|------|--------|
| **MCU** | ESP32-H2 (RISC-V, 96 MHz, 320 KB SRAM) |
| **Radio** | IEEE 802.15.4 @ 2.4 GHz, -97 dBm sensitivity |
| **Protocols** | Zigbee 3.0, Thread 1.3, Matter 1.0+ |
| **Crypto** | Hardware AES-128 CCM* |
| **Display** | 128x64 OLED (SSD1306) |
| **Storage** | MicroSD (PCAP export) |
| **Power** | LiPo battery (USB-C charging) |
| **Firmware** | 5,595 lines of C |
| **Build system** | ESP-IDF v5.4.1 |
| **Form factor** | Pocket-sized (~credit card) |

---

<a id="use-cases"></a>
## Use Cases

### Smart Lock Penetration Testing
Capture pairing keys, replay unlock commands, test disassociation resilience. Find out if your "secure" lock actually is.

### Smart Home Security Audits
Scan a home's Zigbee network, enumerate devices, test for unencrypted traffic, attempt coordinator impersonation. Deliver a real audit report, not a checkbox.

### Matter Pre-Certification Testing
Fuzz ZCL endpoints and test session handling before your Matter device ships. Cheaper than finding out in production.

### Industrial IoT Security Assessment
Thread network discovery and protocol analysis for factory floors, building automation, and critical infrastructure.

### Academic Research and CTF
Hands-on 802.15.4 security training for under $50. Purpose-built for wireless security courses and capture-the-flag competitions.

### Bug Bounty Research
Active testing capability at a price point that doesn't gatekeep independent researchers. Find real vulnerabilities in real products.

---

<a id="hardware"></a>
## Hardware You Need

Total cost: **$30-50** depending on sourcing.

| Component | Approx. Cost | Notes |
|-----------|:---:|-------|
| [ESP32-H2-DevKitM-1](https://www.espressif.com/en/products/devkits/esp32-h2-devkitm-1) | $10 | The brain. RISC-V + 802.15.4 radio. |
| SSD1306 OLED 128x64 (I2C) | $5 | Any 0.96" I2C OLED module works. [AliExpress](https://www.aliexpress.com/wholesale?SearchText=ssd1306+oled+128x64+i2c) / [Amazon](https://www.amazon.com/s?k=ssd1306+oled+128x64) |
| 3.7V LiPo battery + TP4056 charger | $5 | 500-1000mAh recommended. USB-C charging board. |
| MicroSD card module (SPI) | $2 | For PCAP export. Any SPI breakout works. |
| Tactile buttons (x4) | $1 | Navigation: Up, Down, Select, Back |
| Perfboard + wire + enclosure | $5 | Or 3D print a case (STL files in `/hardware/enclosure/`) |

> No soldering iron? The ESP32-H2 DevKit has pin headers. You can breadboard the entire thing in 15 minutes.

---

<a id="quick-start"></a>
## Quick Start

### Prerequisites
- [ESP-IDF v5.4.1](https://docs.espressif.com/projects/esp-idf/en/v5.4.1/esp32h2/get-started/) installed
- USB-C cable
- Assembled hardware (see above)

### Flash and Go

```bash
# Clone
git clone https://github.com/Miles0sage/zigblade.git
cd zigblade/firmware

# Set target
idf.py set-target esp32h2

# Build
idf.py build

# Flash (replace /dev/ttyUSB0 with your port)
idf.py -p /dev/ttyUSB0 flash

# Monitor serial output (optional)
idf.py -p /dev/ttyUSB0 monitor
```

Power on. The OLED shows the main menu. Use the buttons to navigate:

```
  ZIGBLADE v0.1.0
  ----------------
> Channel Scanner
  Packet Sniffer
  Key Extractor
  Injection Tools
  Replay Attack
  Settings
```

That's it. No drivers. No laptop tethered. No license keys.

---

<a id="roadmap"></a>
## Roadmap

### v0.1 -- Foundation (Current)
- [x] Channel scanning (16 channels)
- [x] Passive sniffing with OLED decode
- [x] Auto key extraction (ZigBeeAlliance09)
- [x] Raw packet injection
- [x] Replay attacks
- [x] Beacon flooding
- [x] PCAP export to SD

### v0.2 -- Advanced Attacks
- [x] Disassociation attacks
- [x] Touchlink commissioning attacks
- [x] Coordinator impersonation
- [x] ZCL command fuzzing
- [ ] Green Power device spoofing
- [ ] Network key transport sniffing (insecure rejoin)

### v0.3 -- Multi-Protocol
- [x] Thread network discovery
- [x] Matter session testing
- [ ] Thread credential extraction
- [ ] Matter commissioning interception
- [ ] BLE commissioning attack surface

### v0.4 -- Ecosystem
- [ ] Web UI via ESP32-H2 BLE + companion app
- [ ] Scripting engine (Lua or MicroPython)
- [ ] Plugin system for custom attack modules
- [ ] CI/CD test harness with real hardware

### v1.0 -- Production
- [ ] Custom PCB design (single board, USB-C)
- [ ] Injection-molded enclosure
- [ ] FCC/CE certification for the hardware
- [ ] Comprehensive documentation site

---

<a id="license"></a>
## Why MIT?

ZigBlade is MIT licensed. That means:

- **Use it commercially.** Build a product on top of it. Sell it. No royalties.
- **Modify it freely.** Fork it, rebrand it, gut it, extend it. No restrictions.
- **No copyleft burden.** Unlike GPL, you don't have to open-source your modifications.
- **No non-commercial clause.** Unlike CC BY-NC-ND (looking at you, Kode Dot), you can actually build a business.

Security tools should be accessible. Locking offensive capabilities behind expensive licenses or restrictive terms doesn't make the world safer -- it just means only well-funded attackers have them while defenders and researchers don't.

**If the bad actors already have the tools, the good actors should too.**

---

<a id="contributing"></a>
## Contributing

ZigBlade is built for the security community. Contributions are welcome.

**Good first issues:**
- Add support for new Zigbee device profiles in the fuzzer
- Improve OLED UI animations and menu navigation
- Write Wireshark dissector plugins for ZigBlade-specific metadata
- Add automated test scripts for CI

**Bigger lifts:**
- Thread credential extraction implementation
- Matter commissioning attack modules
- Companion app (BLE bridge to phone/laptop)
- Custom PCB layout

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for guidelines on code style, commit conventions, and the review process.

Before submitting: all firmware must compile cleanly on ESP-IDF v5.4.1 with `-Wall -Werror`. If it doesn't build, it doesn't merge.

---

<p align="center">
  <b>$50. Pocket-sized. Open source. No excuses left for untested smart devices.</b>
</p>

<p align="center">
  <a href="https://github.com/Miles0sage/zigblade">GitHub</a> &bull;
  <a href="https://github.com/Miles0sage/zigblade/issues">Issues</a> &bull;
  <a href="https://github.com/Miles0sage/zigblade/discussions">Discussions</a>
</p>
