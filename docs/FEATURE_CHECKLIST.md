# ZigBlade Feature Checklist — Complete Competitive Parity + Differentiation

> Generated 2026-03-25 from exhaustive web research on Flipper Zero (official + Momentum/Unleashed CFW) and Kode Dot (Kickstarter + docs.kode.diy).
> Status key: HAVE = already in ZigBlade plan | ADD = must add to spec | SKIP = intentionally omit (reason given) | PARTIAL = partially covered

---

## 1. FLIPPER ZERO FEATURES

### 1.1 Hardware Platform

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 1 | MCU | STM32WB55 (Cortex-M4 64MHz + Cortex-M0 32MHz) | HAVE | ESP32-H2 (RISC-V 96MHz) + potential co-processor |
| 2 | RAM | 256 KB | HAVE | ESP32-H2 has 320 KB SRAM |
| 3 | Flash | 1 MB | HAVE | ESP32-H2 has 4 MB flash (expandable) |
| 4 | Display | 128x64 monochrome LCD, orange backlight | ADD | Need display — AMOLED or OLED color would beat Flipper. 128x64 minimum. |
| 5 | Controls | 5-way D-pad + Back button | ADD | Need physical buttons for field use. D-pad + 2 buttons minimum. |
| 6 | Battery | 2000 mAh Li-Po | ADD | Need battery. Target 1000-2000 mAh for pocket device. |
| 7 | microSD slot | Up to 64 GB | ADD | Essential for signal captures, scripts, logs |
| 8 | USB-C | USB 2.0 | HAVE | ESP32-H2 devkit has USB-C |
| 9 | Dimensions | 100.3 x 40.1 x 25.6 mm, 102g | HAVE | Target similar pocket-sized form factor |
| 10 | Tamagotchi pet | Dolphin virtual pet, levels up with usage | SKIP | Novelty feature. Not security-relevant. Could add post-launch as Easter egg. |

### 1.2 Sub-GHz Radio (CC1101)

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 11 | Sub-GHz transceiver | TI CC1101, 300-928 MHz | ADD | Need CC1101 module or equivalent. Critical for garage/gate/remote testing. |
| 12 | Frequency bands | 300-348, 387-464, 779-928 MHz | ADD | Full band coverage required |
| 13 | Modulation | ASK (OOK) + FSK | ADD | Both required for protocol coverage |
| 14 | Read/capture signals | Static code capture & replay | ADD | Core Sub-GHz feature |
| 15 | Read RAW signals | Raw signal recording for unknown protocols | ADD | Essential for unknown protocol analysis |
| 16 | Signal replay/emulation | Transmit captured signals | ADD | Core offensive capability |
| 17 | Add remotes manually | Manual protocol entry (Princeton, CAME, etc.) | ADD | Useful for known protocol testing |
| 18 | Static protocol decode | 30+ vendors (CAME, Nice, Linear, Chamberlain, etc.) | ADD | Full vendor list — see Flipper docs |
| 19 | Rolling code decode | Read-only for KeeLoq, FAAC, Nice FLOR-S, Scher-Khan, StarLine, etc. | ADD | Read + decode. Unleashed/Momentum can replay — we should too. |
| 20 | Rolling code replay | Blocked in official FW, enabled in Momentum/Unleashed | ADD | MUST HAVE for pentest device. This is what users actually want. |
| 21 | Weather station decode | Oregon, LaCrosse, Ambient Weather, etc. | ADD | Nice-to-have for IoT audit scope |
| 22 | TPMS decode | Renault, Toyota, Schrader, Ford, Citroen | SKIP | Low security relevance. Can add via community plugin later. |
| 23 | POCSAG decode | Pager protocol decode | ADD | Useful for signal intelligence in pentesting |
| 24 | Frequency analyzer | Detect active transmissions, show frequency | ADD | Critical field tool for finding unknown signals |
| 25 | Spectrum analyzer | Visual RF spectrum display | ADD | Community app on Flipper — we should have native |
| 26 | GPS sub-driving | Log GPS coords with captured signals (Momentum) | ADD | Wardriving equivalent for Sub-GHz. Needs GPS module. |
| 27 | Extended frequency range | Momentum unlocks 281-361, 378-481, 749-962 MHz | ADD | Ship unlocked from factory. No artificial limits. |
| 28 | ProtoView | Unknown signal analysis (antirez app) | ADD | Signal visualization and protocol reverse engineering |

### 1.3 NFC (13.56 MHz)

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 29 | NFC reader chip | ST25R3916 | ADD | Need dedicated NFC reader IC. ST25R3916 or PN532/PN5180. |
| 30 | ISO 14443-A | Read/emulate | ADD | Most common NFC standard |
| 31 | ISO 14443-B | Read/emulate | ADD | Secondary standard |
| 32 | ISO 15693 | Read/emulate | ADD | Vicinity cards |
| 33 | FeliCa | Read (limited) | ADD | Japanese transit cards |
| 34 | MIFARE Classic | Read + dictionary attack + key recovery + write to magic cards | ADD | Most exploited card type. MFKey32/nonce recovery critical. |
| 35 | MIFARE Ultralight | Read/write/emulate (all variants: UL, UL C, UL 11, UL 21) | ADD | Common in transit/event tickets |
| 36 | NTAG | Read/write/emulate (203, 213, 215, 216, I2C variants) | ADD | Used in amiibo, smart posters, access |
| 37 | MIFARE DESFire | Read UID + app directory (no full emulation) | ADD | Read what we can. Full emulation extremely hard. |
| 38 | EMV (bank cards) | Read UID/SAK/ATQA only (no save) | ADD | Useful for audit, NOT for fraud |
| 39 | NFC emulation | Emulate saved cards | ADD | Core pentest feature |
| 40 | Magic card writing | Write to Gen1a/Gen2 magic cards | ADD | Essential for physical cloning tests |
| 41 | NFC Maker app | Create NDEF records (URL, text, WiFi, BT) | ADD | Momentum feature. Useful for social engineering tests. |
| 42 | Picopass/iCLASS | Via SAM expansion board + Seader app | ADD | HID iCLASS read/downgrade. Very valuable for access control pentesting. |

### 1.4 125 kHz RFID

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 43 | LF RFID reader | Custom analog frontend, 125 kHz | ADD | Need analog circuitry for LF RFID |
| 44 | EM4100 | Read/write/emulate | ADD | Most common LF card |
| 45 | HID Prox (H10301) | Read/write/emulate | ADD | Extremely common in building access |
| 46 | Indala | Read/write/emulate | ADD | Legacy but still deployed |
| 47 | AWID/Viking/Pyramid | Read/write/emulate | ADD | Additional LF protocols |
| 48 | T5577 write | Write cloned data to blank T5577 cards | ADD | Standard RFID cloning card |
| 49 | Keri/Gallagher/PAC | Read/write/emulate | ADD | Full protocol coverage |
| 50 | FDX-A/FDX-B | Animal microchip read | SKIP | Low pentest value. Can add later. |
| 51 | 28+ LF protocols | Full list in Flipper docs | ADD | Target parity with all 28+ protocols |
| 52 | RFID fuzzer | Brute-force RFID codes | ADD | Community app. Important for access control testing. |

### 1.5 Infrared

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 53 | IR transceiver | Read + transmit IR signals | ADD | Simple hardware (IR LED + receiver) |
| 54 | IR learning | Capture and save unknown remotes | ADD | Basic feature |
| 55 | Universal remotes | Pre-built databases for TVs, ACs, projectors, audio | ADD | Crowdsourced IR database |
| 56 | IR brute-force | Try all codes for a brand | ADD | Momentum feature. Useful for testing. |

### 1.6 iButton (1-Wire)

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 57 | iButton reader | Dallas/Maxim 1-Wire contact pad | ADD | Simple hardware — just a contact ring |
| 58 | DS1990A | Read/write/emulate | ADD | Most common iButton |
| 59 | Cyfral | Read/write/emulate | ADD | Russian/CIS access control |
| 60 | Metakom | Read/write/emulate | ADD | Russian/CIS access control |
| 61 | iButton emulation | Emulate saved keys | ADD | Contact-based emulation |

### 1.7 BadUSB / HID

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 62 | USB HID keyboard | Emulate keyboard over USB | ADD | ESP32 can do USB HID natively |
| 63 | DuckyScript support | Rubber Ducky payload language | ADD | Standard attack scripting |
| 64 | Bad-Keyboard (BLE) | Wireless HID over Bluetooth (Momentum) | ADD | BLE HID — ESP32-H2 supports this natively |
| 65 | Mass storage | USB mass storage mode | ADD | For payload delivery |
| 66 | USB Ethernet | Emulate USB Ethernet adapter | ADD | For network-based attacks |

### 1.8 Bluetooth

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 67 | BLE 5.0 | Peripheral + host mode | HAVE | ESP32-H2 has BLE 5.0 (actually 5.2) |
| 68 | BLE Spam | Spam BLE advertisements to Apple/Android/Windows (Momentum) | ADD | Popular feature. ESP32 excels at this. |
| 69 | FindMy/AirTag emulation | Emulate Apple FindMy beacons | ADD | Track your device. ESP32 can do this. |
| 70 | BLE HID | Bluetooth keyboard/mouse emulation | ADD | Native ESP32 capability |
| 71 | Flipper Mobile App | BLE connection to iOS/Android companion app | ADD | Need companion app for ZigBlade (mobile or web) |

### 1.9 GPIO & Hardware Interface

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 72 | GPIO header | 18-pin breakout | ADD | Need expansion header for modules |
| 73 | UART bridge | USB-to-UART | ADD | Essential for hardware hacking |
| 74 | SPI bridge | USB-to-SPI | ADD | Essential for flash dumping |
| 75 | I2C bridge | USB-to-I2C | ADD | Essential for EEPROM/sensor access |
| 76 | 3.3V + 5V power out | Power external devices | ADD | Via GPIO header |
| 77 | Logic analyzer | Built-in digital logic analyzer | ADD | Community app. Useful for protocol RE. |
| 78 | Signal generator | PWM/frequency generation | ADD | For testing and calibration |

### 1.10 U2F / Security

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 79 | U2F Security Key | FIDO U2F authentication | SKIP | Not a pentest feature. Use a YubiKey. |
| 80 | TOTP Authenticator | 2FA code generator (community app) | SKIP | Phone does this better. Not core to mission. |

### 1.11 Software / Ecosystem

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 81 | App store | Flipper Lab app hub | ADD | Need app/plugin system for community extensions |
| 82 | Mobile companion app | iOS + Android | ADD | For configuration, file transfer, remote control |
| 83 | Desktop app (qFlipper) | File manager + firmware update | ADD | Desktop tool for device management |
| 84 | JavaScript runtime | JS scripting on device (Momentum) | ADD | Scripting runtime essential for custom tools |
| 85 | Open source firmware | 100% open source + open hardware | HAVE | Plan is fully open source |
| 86 | CLI interface | Serial command-line interface | ADD | For automation and scripting |
| 87 | File browser | On-device file management | ADD | Navigate captures, scripts, logs |
| 88 | Custom firmware support | Unleashed/Momentum/RogueMaster | HAVE | Open platform = community can fork |
| 89 | OTA firmware update | Update via BLE/WiFi | ADD | ESP32 supports OTA natively |

### 1.12 Flipper Expansion Modules

| # | Feature | Flipper Zero Spec | ZigBlade Status | Notes |
|---|---------|-------------------|-----------------|-------|
| 90 | WiFi Devboard | ESP32-S2 for WiFi attacks (Marauder) | ADD | Need WiFi capability. ESP32-C5 or ESP32-S3 co-processor. |
| 91 | WiFi deauth | Deauthentication attacks via Marauder | ADD | Classic WiFi pentest tool |
| 92 | WiFi scanning | Network discovery + SSID capture | ADD | Standard WiFi audit feature |
| 93 | Captive portal | Evil portal / credential capture | ADD | Social engineering tool |
| 94 | Wardriving | WiFi wardriver with GPS logging (Momentum) | ADD | Needs WiFi + GPS |
| 95 | Video Game Module | RP2040 + video out + motion sensor | SKIP | Entertainment/maker focus. Not security. |
| 96 | SAM Expansion | HID iCLASS/Seos/DESFire reader | ADD | Critical for enterprise access control pentesting |
| 97 | NRF24 module | MouseJack / 2.4 GHz protocol attacks | ADD | Wireless keyboard/mouse hijacking |
| 98 | CC1101 ext antenna | External Sub-GHz for range extension | ADD | Extended range for field work |

---

## 2. KODE DOT FEATURES

### 2.1 Hardware Platform

| # | Feature | Kode Dot Spec | ZigBlade Status | Notes |
|---|---------|---------------|-----------------|-------|
| 99 | MCU | ESP32-S3 (dual-core LX7, 240 MHz) | HAVE | ESP32-H2 is different arch but ZigBlade may add co-processor |
| 100 | Display | 2.13" AMOLED 502x410, capacitive touch | ADD | Color AMOLED would be major upgrade vs Flipper's monochrome |
| 101 | Touch screen | Capacitive touch (CST820) | ADD | Nice-to-have. Physical buttons preferred for security tools, but touch adds UX. |
| 102 | IMU/Motion | BNO086 9-axis (accel + gyro + magnetometer) | SKIP | Maker feature. Not relevant to pentest unless adding air mouse. |
| 103 | Microphone | ICS-43434 digital MEMS mic | ADD | Useful for audio-based attacks, van Eck, acoustic side channels |
| 104 | Speaker | MAX98357A 1W amp | ADD | For alerts, signal playback, audio feedback |
| 105 | RTC | MAX31329 real-time clock | ADD | Timestamp captures and scheduled tasks |
| 106 | RGB LED | WS2812B addressable | ADD | Status indicator. Simple and useful. |
| 107 | Battery | 500 mAh LiPo | HAVE | ZigBlade should target 1000+ mAh |
| 108 | PMIC | BQ25896 + BQ27220 fuel gauge | ADD | Proper power management for battery life |
| 109 | Flash | 32 MB Octal Flash | HAVE | ESP32-H2 can support external flash |
| 110 | PSRAM | 8 MB Octal PSRAM | ADD | For large capture buffers and signal processing |
| 111 | Size | 74 x 43 x 15 mm, 75g | HAVE | Comparable pocket size |

### 2.2 Kode Dot Modules

| # | Feature | Kode Dot Spec | ZigBlade Status | Notes |
|---|---------|---------------|-----------------|-------|
| 112 | Hacking Module | ESP32-C5 + 2x NRF24 + Sub-GHz (CC1101) | ADD | This is basically what ZigBlade needs as expansion. All-in-one radio board. |
| 113 | WiFi 5 GHz | ESP32-C5 adds 5 GHz WiFi | ADD | Most pentest devices lack 5 GHz. Major differentiator. |
| 114 | Camera Module | OV2640 or similar | SKIP | Maker/toy feature. Not security tool. Could add post-launch. |
| 115 | LoRa/Radio Module | SX1262 or similar for LoRa + Meshtastic | ADD | Long-range comms for field teams. Meshtastic is hot. |
| 116 | GPS Module | (part of radio module) | ADD | For wardriving, sub-driving, geolocation of signals |

### 2.3 kodeOS & Software

| # | Feature | Kode Dot Spec | ZigBlade Status | Notes |
|---|---------|---------------|-----------------|-------|
| 117 | Custom OS | kodeOS — apps as installable programs | ADD | Need ZigBlade OS. Menu-driven with app launcher. |
| 118 | App system | Upload code as apps with icons/names | ADD | Plugin/app architecture essential |
| 119 | Arduino compatibility | Code in Arduino IDE | HAVE | ESP-IDF + Arduino support |
| 120 | PlatformIO support | Development in PlatformIO | HAVE | Standard ESP32 toolchain |
| 121 | AI voice control | Connect to GPT/Gemini via WiFi for voice commands | SKIP | Gimmick for maker market. Not relevant for pentest tool. |
| 122 | Pre-loaded apps | Air Mouse, ChatGPT, Meshtastic, Pong, Camera, Pomodoro | SKIP | Maker/consumer apps. ZigBlade ships with security tools. |
| 123 | Open source (planned) | Hardware + firmware on GitHub post-campaign | HAVE | ZigBlade is open source from day one |

### 2.4 Kode Dot Stretch Goal Features

| # | Feature | Kode Dot Spec | ZigBlade Status | Notes |
|---|---------|---------------|-----------------|-------|
| 124 | IR transceiver | $100K goal — TX + RX built in | ADD | Already in Flipper list above (#53-56) |
| 125 | NFC + 125 kHz RFID | $250K goal — both built in | ADD | Already in Flipper list above (#29-52) |
| 126 | Dual-MCU upgrade | $1M goal — ESP32-P4 (400MHz RISC-V) + ESP32-C6 (WiFi 6 + BLE 5 + 802.15.4) | PARTIAL | ESP32-H2 already has 802.15.4. But P4-class compute would be nice for signal processing. Consider dual-MCU. |
| 127 | ESP32-C6 802.15.4 | Thread/Zigbee + WiFi 6 + BLE 5 on one chip | HAVE | ESP32-H2 has 802.15.4 natively. This IS our core advantage. |

---

## 3. FEATURES NEITHER HAS — ZIGBLADE UNIQUE SELLING POINTS

These are ZigBlade's competitive moat. No other pocket device does these.

### 3.1 IEEE 802.15.4 / Zigbee / Thread / Matter (PRIMARY DIFFERENTIATOR)

| # | Feature | Description | Priority | Notes |
|---|---------|-------------|----------|-------|
| 128 | Zigbee sniffing | Passive capture of Zigbee traffic on all channels (11-26) | CRITICAL | ESP32-H2 esp_ieee802154 API supports this natively |
| 129 | Zigbee frame injection | Inject arbitrary 802.15.4 frames | CRITICAL | Raw TX capability confirmed on ESP32-H2 |
| 130 | Zigbee replay attack | Capture and replay Zigbee commands | CRITICAL | Killer demo: replay to unlock smart lock |
| 131 | Zigbee network discovery | Enumerate Zigbee networks, coordinators, routers, end devices | CRITICAL | Map entire Zigbee network topology |
| 132 | Zigbee key extraction | Sniff network key during join (transport key vulnerability) | CRITICAL | Known Zigbee vulnerability — key sent over air during pairing |
| 133 | Zigbee key brute-force | Dictionary attack on Zigbee link keys | HIGH | For networks not using well-known keys |
| 134 | Thread sniffing | Capture Thread mesh traffic | CRITICAL | Thread uses 802.15.4 — same radio |
| 135 | Thread commissioning attack | Exploit Thread commissioning process | HIGH | Research area — novel attacks |
| 136 | Matter protocol analysis | Inspect Matter-over-Thread traffic | CRITICAL | Matter is THE future smart home protocol |
| 137 | Matter commissioning intercept | Analyze Matter pairing/commissioning | HIGH | Security audit of Matter implementations |
| 138 | 802.15.4 channel hopping | Scan all 16 channels (11-26) rapidly | CRITICAL | Full spectrum awareness |
| 139 | 802.15.4 fuzzer | Fuzz 802.15.4 frame fields | HIGH | Find implementation bugs in Zigbee/Thread stacks |
| 140 | Zigbee device impersonation | Spoof as legitimate Zigbee device | HIGH | Inject rogue devices into network |
| 141 | Zigbee coordinator takeover | PAN ID conflict attack, coordinator spoofing | HIGH | Network-level attack |
| 142 | KillerBee compatibility | Support KillerBee Python framework commands | HIGH | Existing security community uses KillerBee |
| 143 | Wireshark live capture | Stream 802.15.4 frames to Wireshark via USB | CRITICAL | Standard pentest workflow integration |
| 144 | Touchlink factory reset | Zigbee Light Link factory reset attack | HIGH | Known attack against Zigbee bulbs/devices |
| 145 | OTA update attack | Intercept/modify Zigbee OTA firmware updates | HIGH | Supply chain attack vector |
| 146 | Green Power sniffing | Capture Zigbee Green Power (energy harvesting devices) | MEDIUM | Emerging device category |

### 3.2 Advanced Security Research Tools

| # | Feature | Description | Priority | Notes |
|---|---------|-------------|----------|-------|
| 147 | Multi-protocol capture | Simultaneous capture across 802.15.4 + BLE | HIGH | Neither Flipper nor Kode Dot can do multi-radio capture |
| 148 | Automated vulnerability scanner | Scan Zigbee network and report known vulns | HIGH | Like nmap but for Zigbee. Killer feature for consultants. |
| 149 | Attack playbooks | Pre-built attack sequences (recon -> exploit -> report) | HIGH | Guided pentesting workflows |
| 150 | Pentest report generator | Auto-generate findings report from captured data | MEDIUM | Export to PDF/JSON for client deliverables |
| 151 | Firmware extraction | SPI flash dump + UART shell for IoT device firmware | HIGH | Hardware hacking integration |
| 152 | Side-channel analysis | Power/timing analysis of crypto operations | MEDIUM | Advanced. Needs ADC. Future feature. |
| 153 | JTAG/SWD debug | Debug interface for target devices | HIGH | Standard hardware RE tool |
| 154 | CAN bus interface | Automotive/industrial protocol (via module) | MEDIUM | Growing IoT attack surface |
| 155 | Z-Wave sniffing | Z-Wave protocol capture (separate radio needed) | MEDIUM | Competitor to Zigbee in smart home |
| 156 | BLE active attacks | MITM, relay, fuzzing of BLE connections | HIGH | BLE security testing beyond simple spam |
| 157 | WiFi + Zigbee simultaneous | Attack WiFi gateway while sniffing Zigbee | HIGH | Dual-radio coordinated attacks |

### 3.3 Software Differentiators

| # | Feature | Description | Priority | Notes |
|---|---------|-------------|----------|-------|
| 158 | Python scripting | MicroPython or CircuitPython on device | HIGH | Security community prefers Python |
| 159 | Scapy-like packet crafting | Build arbitrary 802.15.4 frames from UI or script | CRITICAL | Power user feature for protocol research |
| 160 | Web UI | WiFi-served configuration/control interface | HIGH | Access from phone/laptop without special app |
| 161 | REST API | HTTP API for automation and integration | MEDIUM | For CI/CD security testing pipelines |
| 162 | PCAP export | Standard packet capture format for analysis | CRITICAL | Industry standard, import into Wireshark |
| 163 | Encrypted storage | Encrypt captures and keys on SD card | HIGH | Protect client data during engagements |
| 164 | Headless mode | Run automated scans without display | MEDIUM | Drop device, collect data, retrieve later |
| 165 | Remote control | Control ZigBlade from laptop via WiFi/BLE | HIGH | Field team coordination |
| 166 | Dual-boot | Switch between pentest mode and development mode | MEDIUM | Clean separation of concerns |

---

## 4. SUMMARY SCORECARD

### Must-Have for v1.0 (MVP)

From Flipper Zero:
- [ ] Display + buttons (#4, #5)
- [ ] Battery + power management (#6, #108)
- [ ] microSD storage (#7)
- [ ] BadUSB / USB HID (#62-65)
- [ ] BLE capabilities (#67-70)
- [ ] GPIO/UART/SPI/I2C (#72-76)
- [ ] CLI interface (#86)
- [ ] OTA updates (#89)

From Kode Dot:
- [ ] Color display (beat both competitors) (#100)
- [ ] Speaker for audio feedback (#104)
- [ ] RGB LED status (#106)
- [ ] App/plugin system (#117-118)

ZigBlade Unique (CORE):
- [ ] Zigbee sniffing (#128)
- [ ] Zigbee frame injection (#129)
- [ ] Zigbee replay attack (#130)
- [ ] Zigbee network discovery (#131)
- [ ] Zigbee key extraction (#132)
- [ ] Thread sniffing (#134)
- [ ] Matter analysis (#136)
- [ ] Channel hopping (#138)
- [ ] Wireshark live capture (#143)
- [ ] PCAP export (#162)
- [ ] Scapy-like packet crafting (#159)

### Must-Have for v1.5 (Full Product)

From Flipper Zero:
- [ ] Sub-GHz radio — CC1101 (#11-28)
- [ ] NFC reader — full protocol suite (#29-42)
- [ ] 125 kHz RFID — full protocol suite (#43-52)
- [ ] IR transceiver (#53-56)
- [ ] iButton (#57-61)
- [ ] WiFi attacks via co-processor (#90-94)
- [ ] NRF24 MouseJack (#97)
- [ ] App store / community hub (#81)
- [ ] Mobile companion app (#82)
- [ ] Rolling code support (#19-20)

From Kode Dot:
- [ ] WiFi 5 GHz (#113)
- [ ] LoRa/Meshtastic module (#115)
- [ ] GPS module (#116)

ZigBlade Unique:
- [ ] Automated Zigbee vulnerability scanner (#148)
- [ ] Attack playbooks (#149)
- [ ] BLE active attacks (#156)
- [ ] 802.15.4 fuzzer (#139)
- [ ] Zigbee device impersonation (#140)
- [ ] Python scripting (#158)
- [ ] Web UI (#160)

### Future / v2.0

- [ ] SAM expansion for HID iCLASS (#96)
- [ ] Pentest report generator (#150)
- [ ] Side-channel analysis (#152)
- [ ] CAN bus (#154)
- [ ] Z-Wave (#155)
- [ ] Headless mode (#164)
- [ ] Encrypted storage (#163)

### Intentionally Skipped

| Feature | Reason |
|---------|--------|
| Tamagotchi pet (#10) | Not security-relevant |
| TPMS decode (#22) | Low pentest value, add via plugin if desired |
| Animal microchip (#50) | Not pentest feature |
| U2F key (#79) | Use a dedicated YubiKey |
| TOTP authenticator (#80) | Phone does this better |
| Video Game Module (#95) | Entertainment focus |
| Camera module (#114) | Maker/toy feature |
| IMU/motion sensor (#102) | Not security-relevant |
| AI voice control (#121) | Gimmick |
| Kode Dot pre-loaded apps (#122) | Consumer apps, not security |

---

## 5. HARDWARE BOM IMPLICATIONS

### Core Board (v1.0 MVP)
- ESP32-H2 (main MCU — Zigbee/Thread/BLE)
- OLED/AMOLED display (128x128 or better)
- 5-way D-pad + 2 buttons
- microSD slot
- USB-C
- 1000+ mAh LiPo
- BQ25896 PMIC + fuel gauge
- RGB LED
- Piezo/speaker
- GPIO expansion header (20+ pins)

### Radio Expansion Board (v1.5)
- CC1101 (Sub-GHz)
- ST25R3916 or PN5180 (NFC 13.56 MHz)
- 125 kHz RFID analog frontend
- IR LED + IR receiver
- iButton contact pad
- ESP32-C5 or ESP32-S3 (WiFi 2.4+5 GHz co-processor)
- NRF24L01+ (2.4 GHz)

### Optional Modules
- GPS (u-blox or similar)
- LoRa (SX1262)
- SAM card reader (for HID iCLASS)
- External antenna connectors (SMA/U.FL)

---

## 6. COMPETITIVE POSITIONING

```
                    Flipper Zero    Kode Dot       ZigBlade
                    -----------     --------       --------
Sub-GHz             YES             YES (module)   YES (module)
NFC                 YES             YES (basic)    YES
125 kHz RFID        YES             YES            YES
IR                  YES             YES            YES
iButton             YES             NO             YES
BadUSB              YES             NO             YES
BLE                 YES             YES            YES
WiFi                Module          Module         Module
Zigbee              PARTIAL*        NO             NATIVE (CORE)
Thread              PARTIAL*        NO             NATIVE (CORE)
Matter              NO              NO             YES (CORE)
802.15.4 Injection  NO              NO             YES (CORE)
Frame Fuzzing       NO              NO             YES
Wireshark Stream    NO              NO             YES
Python Scripting    NO              Arduino only   YES
Color Display       NO              YES            YES
Touch Screen        NO              YES            OPTIONAL
5 GHz WiFi          NO              YES (module)   YES (module)
LoRa/Meshtastic     NO              YES (module)   YES (module)
Open Source          YES             Planned        YES (day one)
Price               $169            ~$129+         $199-299 target

* Flipper's STM32WB55 has 802.15.4 radio but firmware support is
  experimental, requires disabling BLE, and lacks injection/attack tools.
```

**ZigBlade's pitch in one sentence:**
"Everything Flipper Zero does for Sub-GHz/NFC/RFID, plus the ONLY pocket device that can actively attack Zigbee, Thread, and Matter networks."

---

Sources:
- [Flipper Zero Tech Specs](https://docs.flipper.net/zero/development/hardware/tech-specs)
- [Flipper Zero Documentation](https://docs.flipper.net/zero)
- [Flipper Zero Sub-GHz Supported Vendors](https://docs.flipper.net/zero/sub-ghz/supported-vendors)
- [Flipper Zero Wikipedia](https://en.wikipedia.org/wiki/Flipper_Zero)
- [Momentum Firmware](https://momentum-fw.dev/)
- [Momentum Firmware GitHub](https://github.com/Next-Flip/Momentum-Firmware)
- [Awesome Flipper Zero](https://github.com/djsime1/awesome-flipperzero)
- [Kode Dot Official](https://www.kode.diy/)
- [Kode Dot Documentation](https://docs.kode.diy/)
- [Kode Dot Kickstarter](https://www.kickstarter.com/projects/kode/kode-dot-the-all-in-one-pocket-size-maker-device/)
- [Kode Dot Review (513.toys)](https://513.toys/kode-dot/)
- [Kode Dot Review (GizmoCrowd)](https://www.gizmocrowd.com/post/kode-dot-device-kickstarter)
- [Kode Dot XDA Review](https://www.xda-developers.com/kode-dot-same-feeling-flipper-zero-esp32/)
- [Kode Dot Hackster.io](https://www.hackster.io/Luismi_Kode/kode-dot-the-all-in-one-device-for-makers-hackers-geeks-3e8315)
- [Flipper Zero RFID Protocols](https://blog.flipper.net/rfid/)
- [Seader (HID SAM)](https://github.com/bettse/seader)
- [Flipper Zero Sub-GHz Guide](https://serverman.co.uk/everything-hardware/everything-flipper-zero/flipper-zero-sub-ghz-guide/)
- [Thread Support for Flipper Zero (CUJO AI)](https://cujo.com/blog/thread-support-for-flipper-zero-part-1-introduction/)
- [ESP32-P4 SoC (Espressif)](https://www.espressif.com/en/products/socs/esp32-p4)
- [ESP32-C6 SoC (Espressif)](https://www.espressif.com/en/products/socs/esp32-c6)
