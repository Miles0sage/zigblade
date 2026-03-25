# ZigBlade Display Mockups

> Visual reference for the ZigBlade UI on 128x64 OLED (SSD1306) and 240x280 color TFT (ST7789).
> All OLED mockups use a 21-character x 8-line grid (5x7 font at 6x8 pixel cells).

---

## Device Concept Art

### Top View

```
          ┌─────────────────────────────────────────────┐
          │  ○ SMA                           SMA ○      │
          │  ║ (Zigbee)                 (BLE) ║         │
          ├──╨─────────────────────────────────╨────────┤
          │                                             │
          │    ┌───────────────────────────────┐        │
          │    │░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│        │
          │    │░░░░░  128x64 OLED  ░░░░░░░░░░│        │
          │    │░░░░░   SSD1306     ░░░░░░░░░░│        │
          │    │░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│        │
          │    └───────────────────────────────┘        │
          │                                             │
          │      [UP]                                   │
          │  [LEFT] [OK] [RIGHT]        [A]  [B]        │
          │      [DOWN]                                 │
          │                                             │
          │  ● LED (status)              ○ USB-C        │
          ├─────────────────────────────────────────────┤
          │  ESP32-H2  │  nRF52840  │  CC2652R  │  BAT  │
          │  (main)    │  (sniffer) │  (inject) │  LiPo │
          └─────────────────────────────────────────────┘

                       ~ 90mm x 55mm ~
```

### Side View

```
          ╔══════════════════════════════════════╗
          ║  antenna  ┃        OLED        ┃     ║  ← 6mm top shell
          ╠══════════════════════════════════════╣
          ║  PCB  ESP32-H2  nRF52  CC2652  LiPo ║  ← 8mm main body
          ╚══════════════════════════════════════╝
                        ~ 14mm total ~

          USB-C port →  ▐████▌  ← flush with edge
```

### Exploded View

```
                    ┌──────────────────┐
                    │   Top Shell      │  ABS / 3D-printed
                    │   (display       │
                    │    cutout)       │
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │   OLED Module    │  0.96" I2C
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │   Main PCB       │  ESP32-H2 + radios
                    │   + buttons      │
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │   LiPo Battery   │  1000mAh 3.7V
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │   Bottom Shell   │  rubber feet
                    └──────────────────┘
```

---

## Screen 1: Splash Screen

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│                     │
│   /\/\/\/\/\/\/\    │
│                     │
│    ╔═╗ ZIGBLADE     │
│    ╚═╝  v0.1.0     │
│                     │
│   \/\/\/\/\/\/\/    │
│                     │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│                              │  BG: black
│                              │
│    /\/\/\/\/\/\/\/\/\/\      │  cyan zigzag
│                              │
│                              │
│     ███████╗██╗██████╗       │  white bold
│          ██║██║██║  ██║      │
│     ╔════╝ ██║██████╔╝      │  "ZIG" large
│     ██╔══╝ ██║██║  ██║      │
│     ███████║██║██████╔╝      │
│     ╚══════╝╚═╝╚═════╝      │
│        B L A D E             │  red accent
│                              │
│    \/\/\/\/\/\/\/\/\/\/      │  cyan zigzag
│                              │
│      v0.1.0 • ESP32-H2      │  gray text
│   802.15.4 Offensive Tool    │  gray text
└──────────────────────────────┘
```

---

## Screen 2: Main Menu

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ ZIGBLADE        ▂▄▆ │  ← battery icon
│─────────────────────│
│ ▸ Scan Networks     │  ← selected (inverted)
│   Sniffer           │
│   Inject            │
│   Attacks           │
│   PCAP Replay       │
│   Settings      ▼   │  ← scroll indicator
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ⚡ ZIGBLADE         🔋 87%  │  white on dark blue bar
│──────────────────────────────│
│                              │
│   ┌──────────────────────┐   │
│   │ ◉  Scan Networks     │   │  selected: cyan bg
│   └──────────────────────┘   │
│   │ ○  Sniffer           │   │  white text
│   │ ○  Inject            │   │  white text
│   │ ○  Attacks           │   │  red text
│   │ ○  PCAP Replay       │   │  white text
│   │ ○  Settings          │   │  gray text
│                              │
│                              │
│  UP/DN: navigate  OK: select │  dim footer
│  CH:15  TX:0dBm  PKT:0      │  status bar green
└──────────────────────────────┘
```

---

## Screen 3: Scan Progress

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ SCANNING...         │
│─────────────────────│
│ Channel:  15 / 26   │
│ Found:     3 nets   │
│ Packets: 147        │
│                     │
│ [████████████░░░░░] │  ← 58% progress
│              58%    │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ← Back          SCANNING    │  title bar
│──────────────────────────────│
│                              │
│         ◠ ◡ ◠ ◡ ◠           │  animated radar
│       ◠       ◡              │  cyan rings
│         ◡ ◠ ◡ ◠ ◡           │
│                              │
│   Channel     ███ 15 / 26   │  green progress
│   Networks         3 found  │  white
│   Packets          147      │  white
│   Beacons          12       │  yellow
│   Devices          5        │  cyan
│                              │
│   ┌──────────────────────┐   │
│   │████████████░░░░░░░░░░│   │  cyan bar on dark
│   └──────────────────────┘   │
│           58%                │  centered
└──────────────────────────────┘
```

---

## Screen 4: Scan Results

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ RESULTS    3 found  │
│─────────────────────│
│▸0x1A2B CH15 -42dBm │  ← selected
│ 0x3C4D CH20 -67dBm │
│ 0xFFE1 CH25 -81dBm │
│                     │
│─────────────────────│
│ OK:detail  B:export │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ← Back       SCAN RESULTS   │
│──────────────────────────────│
│                              │
│  ┌────────────────────────┐  │
│  │ PAN: 0x1A2B            │  │  selected: cyan border
│  │ CH: 15  RSSI: -42 dBm │  │  signal: green (strong)
│  │ Devices: 3   ████▏    │  │  signal bar
│  └────────────────────────┘  │
│  ┌────────────────────────┐  │
│  │ PAN: 0x3C4D            │  │  white border
│  │ CH: 20  RSSI: -67 dBm │  │  signal: yellow
│  │ Devices: 1   ██▏      │  │
│  └────────────────────────┘  │
│  ┌────────────────────────┐  │
│  │ PAN: 0xFFE1            │  │  white border
│  │ CH: 25  RSSI: -81 dBm │  │  signal: red (weak)
│  │ Devices: 0   █▏       │  │
│  └────────────────────────┘  │
│  OK: details  A: export      │
└──────────────────────────────┘
```

---

## Screen 5: Live Sniffer

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ SNIFFER CH15  ● REC │  ← ● blinks red
│─────────────────────│
│ PKT#: 1,247         │
│ Rate: 23/s          │
│─────────────────────│
│ Last: BEACON        │
│  0x1A2B→0xFFFF      │
│  Seq:0A Len:42      │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ← Stop     LIVE SNIFFER     │
│──────────────────────────────│
│  CH: 15          ● REC       │  ● blinks red/dark
│  Packets: 1,247              │  white, large font
│  Rate: 23 pkt/s             │  green
│  Errors: 0                   │  green (red if > 0)
│──────────────────────────────│
│  LATEST PACKET               │  yellow header
│  ┌────────────────────────┐  │
│  │ Type: BEACON           │  │  cyan
│  │ Src:  0x1A2B           │  │  white
│  │ Dst:  0xFFFF (bcast)   │  │  dim white
│  │ Seq:  0x0A             │  │  white
│  │ Len:  42 bytes         │  │  white
│  │ RSSI: -44 dBm  ████▏  │  │  green bar
│  └────────────────────────┘  │
│  A: filter  B: save PCAP     │  dim footer
└──────────────────────────────┘
```

---

## Screen 6: Packet Detail

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ PKT #1247   BEACON  │
│─────────────────────│
│ Src: 0x1A2B         │
│ Dst: 0xFFFF         │
│ Seq: 0x0A  Len:42   │
│─────────────────────│
│ 08 03 FF FF 2B 1A   │  ← hex payload
│ 0A 00 1C 08 22 ...  │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ← Back      PACKET DETAIL   │
│──────────────────────────────│
│  #1247            BEACON     │  type in cyan badge
│                              │
│  ┌─ HEADER ──────────────┐   │  section: yellow
│  │ Frame Type:  Beacon   │   │
│  │ Src Addr:    0x1A2B   │   │  white
│  │ Dst Addr:    0xFFFF   │   │  dim (broadcast)
│  │ Src PAN:     0x1A2B   │   │
│  │ Sequence:    0x0A     │   │
│  └───────────────────────┘   │
│  ┌─ PAYLOAD (42 bytes) ──┐   │  section: green
│  │ 08 03 FF FF 2B 1A 0A │   │  monospace, green
│  │ 00 1C 08 22 11 0E 3B │   │  on dark bg
│  │ A7 C4 5F 02 00 00 00 │   │
│  └───────────────────────┘   │
│  A: replay  B: save          │  dim footer
└──────────────────────────────┘
```

---

## Screen 7: Attack Menu

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ ATTACKS         ⚠   │  ← warning icon
│─────────────────────│
│ ▸ Touchlink Comm.   │  ← selected
│   Key Extract       │
│   Coord. Spoof      │
│   ZCL Fuzzer        │
│   Replay Attack     │
│   Deauth        ▼   │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ← Back       ⚠  ATTACKS     │  red title bar
│──────────────────────────────│
│                              │
│  ┌────────────────────────┐  │
│  │ ▸ Touchlink Commission │  │  selected: red bg
│  └────────────────────────┘  │
│  │   Key Extract          │  │  white
│  │   Coordinator Spoof    │  │  white
│  │   ZCL Fuzzer           │  │  white
│  │   Replay Attack        │  │  white
│  │   Deauth Flood         │  │  white
│  │   Beacon Spoof         │  │  white
│  │   Network Hijack       │  │  white
│                              │
│  ⚠  FOR AUTHORIZED USE ONLY │  red warning text
│  OK: select    B: back       │  dim footer
└──────────────────────────────┘
```

---

## Screen 8: Attack Running

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ ⚠ REPLAY ATTACK     │
│─────────────────────│
│ Target: 0x1A2B      │
│ Status: RUNNING     │
│ Sent:   34 / 100    │
│                     │
│ [███████░░░░░░░░░░] │  ← 34% progress
│ B:ABORT     34%     │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ■ STOP        ATTACK LIVE   │  red pulsing header
│──────────────────────────────│
│                              │
│     ╔══════════════════╗     │
│     ║  REPLAY ATTACK   ║     │  white on red box
│     ╚══════════════════╝     │
│                              │
│   Target PAN:  0x1A2B        │  white
│   Target Dev:  0x0001        │  white
│   Channel:     15            │  white
│   Status:      RUNNING       │  green, blinking
│   Packets TX:  34 / 100     │  cyan
│   Errors:      0             │  green
│                              │
│   ┌──────────────────────┐   │
│   │███████░░░░░░░░░░░░░░░│   │  red bar on dark
│   └──────────────────────┘   │
│        34%  ~12s left        │
└──────────────────────────────┘
```

---

## Screen 9: Settings

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ SETTINGS            │
│─────────────────────│
│ ▸TX Power:  0 dBm   │  ← selected
│  Bright:    80%     │
│  Auto-save: ON      │
│  Channel:   15      │
│  Interface: H2      │
│  USB Mode:  CDC     │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ← Back         SETTINGS     │
│──────────────────────────────│
│                              │
│  ┌────────────────────────┐  │
│  │ TX Power          0 dBm│  │  selected: cyan
│  │  ◄──────●──────────► │  │  slider visual
│  └────────────────────────┘  │
│  │ Brightness         80% │  │
│  │ Auto-save PCAP      ON │  │  green ON
│  │ Default Channel     15 │  │
│  │ Radio Interface     H2 │  │
│  │ USB Mode           CDC │  │
│  │ LED Brightness     50% │  │
│  │ Sleep Timeout     5min │  │
│  │ Factory Reset     ───→ │  │  red text
│                              │
│  LEFT/RIGHT: adjust value    │  dim footer
│  OK: confirm   B: back       │
└──────────────────────────────┘
```

---

## Screen 10: About

### OLED (128x64 / 21x8)

```
┌─────────────────────┐
│ ABOUT               │
│─────────────────────│
│ ZigBlade v0.1.0     │
│ ESP32-H2 + nRF52    │
│ MAC:AA:BB:CC:DD:EE  │
│ FW: 2026-03-25      │
│─────────────────────│
│ github/zigblade     │
└─────────────────────┘
```

### Color TFT (240x280 / ~30x17)

```
┌──────────────────────────────┐
│  ← Back           ABOUT      │
│──────────────────────────────│
│                              │
│        /\/\ ZIGBLADE /\/\    │  cyan zigzag + white
│                              │
│   Version:    0.1.0          │  white
│   Build:      2026-03-25     │  gray
│   Chip:       ESP32-H2      │  white
│   Co-proc:    nRF52840       │  white
│   MAC:        AA:BB:CC:DD:EE│  monospace, cyan
│   Flash:      4MB (62% used)│  yellow if >80%
│   Heap Free:  142KB         │  green
│                              │
│   ┌────────────────────────┐ │
│   │ github.com/Miles0sage  │ │  blue, underlined
│   │       /zigblade        │ │
│   └────────────────────────┘ │
│        Made with ⚡          │  dim gray
└──────────────────────────────┘
```

---

## Navigation Map

```
                      ┌─────────┐
                      │ SPLASH  │
                      └────┬────┘
                           │ (auto 2s)
                      ┌────┴────┐
              ┌───────┤  MAIN   ├───────┐
              │       │  MENU   │       │
              │       └────┬────┘       │
         ┌────┴───┐   ┌───┴────┐  ┌────┴────┐
         │  SCAN  │   │SNIFFER │  │ ATTACKS │
         └───┬────┘   └───┬────┘  └────┬────┘
             │            │            │
        ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
        │PROGRESS │  │  LIVE   │  │ ATTACK  │
        └────┬────┘  │ CAPTURE │  │  MENU   │
             │       └────┬────┘  └────┬────┘
        ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
        │RESULTS  │  │ PACKET  │  │ ATTACK  │
        │  LIST   │  │ DETAIL  │  │ RUNNING │
        └─────────┘  └─────────┘  └─────────┘

         ┌─────────┐  ┌─────────┐
         │SETTINGS │  │  ABOUT  │
         └─────────┘  └─────────┘

  Navigation:  UP/DOWN = scroll    LEFT = back
               OK = select         A/B = context actions
```

---

## Display Specifications

| Property          | OLED (v1)         | Color TFT (v2)       |
|-------------------|-------------------|-----------------------|
| Controller        | SSD1306           | ST7789                |
| Resolution        | 128x64            | 240x280               |
| Colors            | Monochrome (white)| 65K RGB565            |
| Interface         | I2C               | SPI                   |
| Char Grid (approx)| 21 x 8           | 30 x 17               |
| Font              | 5x7 bitmap        | 8x13 + icons          |
| Refresh           | ~30 FPS           | ~60 FPS               |
| Power             | ~20mA             | ~25mA (backlit)       |

## Color Palette (TFT)

| Element           | Color             | Hex        |
|-------------------|-------------------|------------|
| Background        | Near-black        | `#0A0A0A`  |
| Primary text      | White             | `#FFFFFF`  |
| Secondary text    | Gray              | `#888888`  |
| Accent / selected | Cyan              | `#00E5FF`  |
| Warning / attack  | Red               | `#FF1744`  |
| Success / OK      | Green             | `#00E676`  |
| Caution           | Yellow            | `#FFEA00`  |
| Signal strong     | Green             | `#00E676`  |
| Signal medium     | Yellow            | `#FFEA00`  |
| Signal weak       | Red               | `#FF1744`  |
| Header bar        | Dark blue         | `#0D47A1`  |

## Font Assets Needed

```
fonts/
  font_5x7.h        ← OLED bitmap font (ASCII 0x20-0x7E)
  font_8x13.h       ← TFT main font
  font_8x13_bold.h  ← TFT headers
  icons_16x16.h     ← battery, signal, lock, warning, antenna
  icons_8x8.h       ← arrows, checkmarks, radio buttons
```

---

## Implementation Notes

1. **OLED rendering** uses a 1-bit framebuffer (128x64 / 8 = 1024 bytes). Draw to buffer, then flush over I2C.
2. **Inverted selection** on OLED: draw white rectangle behind selected menu item, render text in black.
3. **Blinking elements** (REC indicator, attack status): toggle visibility on a 500ms timer.
4. **Scroll indicators** (arrows): show when list has items above/below the visible window.
5. **Progress bars**: calculated as `(current * bar_width) / total` in pixels.
6. **TFT upgrade path**: same screen state machine, different render backend. Abstract the draw calls behind `display_draw_text()`, `display_draw_rect()`, etc.
7. **Screen timeout**: dim after 30s idle, sleep after 60s. Any button press wakes.
