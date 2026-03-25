"""
ZigBlade Personality — Pwnagotchi-style AI personality system.
Tracks mood, XP, achievements. Sends state to T-Embed display.
"""
import random
from dataclasses import dataclass, field
from datetime import datetime


FACES = {
    "happy": "(◕‿◕)",
    "excited": "(★‿★)",
    "hunting": "(◉_◉)",
    "bored": "(≖_≖)",
    "sad": "(╥_╥)",
    "angry": "(ಠ_ಠ)",
    "sleeping": "(‐_‐)",
    "cool": "(⌐■_■)",
    "thinking": "(◔_◔)",
}

ACHIEVEMENTS = {
    "first_scan": {"name": "Scout", "desc": "First network scan", "xp": 10},
    "first_key": {"name": "Locksmith", "desc": "First key extracted", "xp": 100},
    "ten_networks": {"name": "Cartographer", "desc": "10 networks discovered", "xp": 50},
    "hundred_packets": {"name": "Wiretapper", "desc": "100 packets captured", "xp": 25},
    "first_vuln": {"name": "Bug Hunter", "desc": "First vulnerability found", "xp": 75},
    "touchlink": {"name": "Thief", "desc": "First touchlink steal", "xp": 200},
    "full_report": {"name": "Analyst", "desc": "First pentest report", "xp": 50},
}


@dataclass
class ZigBladePersonality:
    name: str = "ZigBlade"
    mood: str = "happy"
    xp: int = 0
    level: int = 1
    networks_found: int = 0
    keys_extracted: int = 0
    packets_captured: int = 0
    vulns_found: int = 0
    achievements: list[str] = field(default_factory=list)

    @property
    def face(self) -> str:
        return FACES.get(self.mood, FACES["happy"])

    @property
    def xp_to_next(self) -> int:
        return self.level * 100

    def _check_level(self):
        while self.xp >= self.xp_to_next:
            self.xp -= self.xp_to_next
            self.level += 1
            print(f"🎉 LEVEL UP! {self.name} is now level {self.level}!")

    def _earn(self, achievement_id: str):
        if achievement_id not in self.achievements:
            ach = ACHIEVEMENTS.get(achievement_id)
            if ach:
                self.achievements.append(achievement_id)
                self.xp += ach["xp"]
                print(f"🏆 Achievement: {ach['name']} — {ach['desc']} (+{ach['xp']} XP)")
                self._check_level()

    def greet(self):
        greetings = [
            f"{self.face} ZigBlade online. Let's hunt.",
            f"{self.face} Ready to scan. Show me the airwaves.",
            f"{self.face} Level {self.level}. {self.xp}/{self.xp_to_next} XP. Let's go.",
        ]
        print(random.choice(greetings))

    def on_action(self, action: str):
        if action == "scanning":
            self.mood = "hunting"
            print(f"{self.face} Scanning the airwaves...")
        elif action == "sniffing":
            self.mood = "thinking"
            print(f"{self.face} Listening...")
        elif action == "attacking":
            self.mood = "angry"
            print(f"{self.face} Engaging target.")

    def on_discovery(self, count: int):
        self.networks_found += count
        if count > 0:
            self.mood = "excited"
            print(f"{self.face} Found {count} network{'s' if count > 1 else ''}!")
            self._earn("first_scan")
            if self.networks_found >= 10:
                self._earn("ten_networks")
        else:
            self.mood = "bored"
            print(f"{self.face} Nothing here... let's move.")

    def on_key_extracted(self):
        self.keys_extracted += 1
        self.mood = "cool"
        print(f"{self.face} Got a key. {self.keys_extracted} total.")
        self._earn("first_key")
        self.xp += 50
        self._check_level()

    def on_finding(self, severity: str):
        self.vulns_found += 1
        if severity in ("CRITICAL", "HIGH"):
            self.mood = "excited"
            print(f"{self.face} Found something juicy!")
        else:
            self.mood = "happy"
        self._earn("first_vuln")
        self.xp += {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 25, "LOW": 10, "INFO": 5}.get(severity, 5)
        self._check_level()

    def on_empty(self):
        self.mood = "sad"
        print(f"{self.face} No networks found. Are we in a Faraday cage?")

    def on_complete(self, vuln_count: int):
        if vuln_count > 5:
            self.mood = "cool"
            print(f"{self.face} {vuln_count} vulns. This network is Swiss cheese.")
        elif vuln_count > 0:
            self.mood = "happy"
            print(f"{self.face} Found {vuln_count} issues. Good hunt.")
        else:
            self.mood = "sad"
            print(f"{self.face} Network looks solid. Respect.")
        self._earn("full_report")

    def get_display_state(self) -> dict:
        return {
            "face": self.face,
            "mood": self.mood,
            "level": self.level,
            "xp": self.xp,
            "xp_max": self.xp_to_next,
            "networks": self.networks_found,
            "keys": self.keys_extracted,
            "vulns": self.vulns_found,
            "achievements": len(self.achievements),
        }
