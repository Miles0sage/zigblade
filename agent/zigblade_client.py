"""
ZigBlade HTTP/WebSocket Client
Connects to T-Embed WiFi AP and controls the device.
"""
import json
import time
import requests
from dataclasses import dataclass, field
from typing import Optional

ZIGBLADE_BASE = "http://192.168.4.1"


@dataclass
class ZigbeeNetwork:
    pan_id: int
    channel: int
    coordinator: str
    rssi: int
    security: bool
    device_count: int
    zigbee_version: str = "unknown"
    security_assessment: str = "UNKNOWN"


@dataclass
class CapturedPacket:
    timestamp: float
    channel: int
    rssi: int
    frame_type: str
    src_addr: str
    dst_addr: str
    pan_id: int
    payload_hex: str
    decoded: dict = field(default_factory=dict)


@dataclass
class ExtractedKey:
    network_key: str
    pan_id: int
    channel: int
    method: str  # "transport_key" | "install_code" | "brute_force"
    timestamp: float


class ZigBladeClient:
    """HTTP client for ZigBlade T-Embed web UI API."""

    def __init__(self, base_url: str = ZIGBLADE_BASE, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _get(self, path: str) -> dict:
        resp = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: Optional[dict] = None) -> dict:
        resp = self.session.post(
            f"{self.base_url}{path}", json=data or {}, timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()

    # --- Status ---
    def get_status(self) -> dict:
        return self._get("/api/status")

    def is_connected(self) -> bool:
        try:
            status = self.get_status()
            return status.get("online", False)
        except Exception:
            return False

    # --- Scanning ---
    def start_scan(self, channel: Optional[int] = None) -> dict:
        data = {"channel": channel} if channel else {"channel": 0xFF}
        return self._post("/api/scan", data)

    def get_scan_results(self) -> list[ZigbeeNetwork]:
        raw = self._get("/api/scan/results")
        return [
            ZigbeeNetwork(
                pan_id=n["pan_id"],
                channel=n["channel"],
                coordinator=n["coordinator"],
                rssi=n["rssi"],
                security=n["security"],
                device_count=n.get("device_count", 0),
                zigbee_version=n.get("zigbee_version", "unknown"),
                security_assessment=n.get("assessment", "UNKNOWN"),
            )
            for n in raw.get("networks", [])
        ]

    def scan_and_wait(self, timeout: int = 30) -> list[ZigbeeNetwork]:
        self.start_scan()
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.get_status()
            if not status.get("scanning", True):
                break
            time.sleep(1)
        return self.get_scan_results()

    # --- Sniffing ---
    def start_sniff(self, channel: int, key: Optional[str] = None) -> dict:
        data = {"channel": channel}
        if key:
            data["key"] = key
        return self._post("/api/sniff", data)

    def stop_sniff(self) -> dict:
        return self._post("/api/sniff/stop")

    def get_packets(self, since: int = 0) -> list[CapturedPacket]:
        raw = self._get(f"/api/packets?since={since}")
        return [
            CapturedPacket(
                timestamp=p["timestamp"],
                channel=p["channel"],
                rssi=p["rssi"],
                frame_type=p["frame_type"],
                src_addr=p["src_addr"],
                dst_addr=p["dst_addr"],
                pan_id=p["pan_id"],
                payload_hex=p["payload_hex"],
                decoded=p.get("decoded", {}),
            )
            for p in raw.get("packets", [])
        ]

    # --- Keys ---
    def get_keys(self) -> list[ExtractedKey]:
        raw = self._get("/api/keys")
        return [
            ExtractedKey(
                network_key=k["key"],
                pan_id=k["pan_id"],
                channel=k["channel"],
                method=k["method"],
                timestamp=k["timestamp"],
            )
            for k in raw.get("keys", [])
        ]

    # --- Attacks ---
    def attack_replay(self, packet_index: int) -> dict:
        return self._post("/api/attack", {"type": "replay", "target": packet_index})

    def attack_touchlink(self, target_addr: Optional[str] = None) -> dict:
        data = {"type": "touchlink"}
        if target_addr:
            data["target"] = target_addr
        return self._post("/api/attack", data)

    def attack_disassoc(self, target_addr: str) -> dict:
        return self._post("/api/attack", {"type": "disassoc", "target": target_addr})

    def attack_beacon_flood(self, pan_id: int) -> dict:
        return self._post("/api/attack", {"type": "beacon_flood", "pan_id": pan_id})

    def attack_fuzz(self, target_addr: str) -> dict:
        return self._post("/api/attack", {"type": "fuzz", "target": target_addr})

    def get_attack_status(self) -> dict:
        return self._get("/api/attack/status")

    # --- Settings ---
    def set_channel(self, channel: int) -> dict:
        return self._post("/api/settings", {"channel": channel})

    def set_tx_power(self, power_dbm: int) -> dict:
        return self._post("/api/settings", {"tx_power": power_dbm})

    # --- PCAP ---
    def download_pcap(self, filename: str = "capture.pcap") -> bytes:
        resp = self.session.get(
            f"{self.base_url}/api/pcap/download", timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.content
