"""
ZigBlade AI Agent — Autonomous IoT Security Assessment
Connects to ZigBlade device via WiFi, uses Claude API for decision making.
Authorized security testing only.
"""
import os
import json
import time
from datetime import datetime
from typing import Optional
from anthropic import Anthropic
from zigblade_client import ZigBladeClient, ZigbeeNetwork, CapturedPacket, ExtractedKey
from report_generator import ReportGenerator
from personality import ZigBladePersonality

SYSTEM_PROMPT = """You are ZigBlade AI, an autonomous IoT security assessment agent.
You control a ZigBlade hardware device that can scan, sniff, and test Zigbee/Thread/Matter networks.

You have these tools via the ZigBlade API:
- scan_networks() — discover all Zigbee networks in range
- sniff_channel(ch) — capture packets on a channel
- get_keys() — check if any network keys were extracted
- attack_replay(pkt) — replay a captured packet (authorized testing only)
- attack_touchlink(addr) — touchlink commissioning test
- attack_disassoc(addr) — disassociation test
- attack_fuzz(addr) — ZCL fuzzing test
- get_status() — device status

Your job:
1. Scan and discover networks
2. Assess each network's security posture
3. Identify vulnerabilities
4. Recommend (or execute if authorized) appropriate tests
5. Generate a professional pentest report

Rules:
- Only test networks the operator has authorized
- Log everything
- Rate findings by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Be methodical — scan first, analyze, then test
- Never cause permanent damage to devices
"""


class ZigBladeAgent:
    """AI-powered autonomous security assessment agent."""

    def __init__(
        self,
        device_url: str = "http://192.168.4.1",
        auto_attack: bool = False,
        api_key: Optional[str] = None,
    ):
        self.client = ZigBladeClient(base_url=device_url)
        self.claude = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.personality = ZigBladePersonality()
        self.reporter = ReportGenerator()
        self.auto_attack = auto_attack
        self.findings: list[dict] = []
        self.networks: list[ZigbeeNetwork] = []
        self.keys: list[ExtractedKey] = []
        self.packets: list[CapturedPacket] = []
        self.log: list[dict] = []
        self.session_start = datetime.now()

    def _log(self, action: str, detail: str, level: str = "INFO"):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "detail": detail,
            "level": level,
        }
        self.log.append(entry)
        icon = {"INFO": "ℹ️", "WARN": "⚠️", "VULN": "🔴", "OK": "✅"}.get(level, "📝")
        print(f"{icon} [{action}] {detail}")

    def _add_finding(self, severity: str, title: str, description: str, evidence: str = ""):
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        self._log("FINDING", f"[{severity}] {title}", "VULN" if severity in ("CRITICAL", "HIGH") else "WARN")
        self.personality.on_finding(severity)

    def _ask_claude(self, context: str, question: str) -> str:
        response = self.claude.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Context:\n{context}\n\nQuestion:\n{question}"}
            ],
        )
        return response.content[0].text

    # --- Phase 1: Discovery ---
    def phase_discover(self) -> list[ZigbeeNetwork]:
        self._log("SCAN", "Starting network discovery on all 16 channels")
        self.personality.on_action("scanning")
        self.networks = self.client.scan_and_wait(timeout=45)
        self._log("SCAN", f"Found {len(self.networks)} networks")
        self.personality.on_discovery(len(self.networks))

        for net in self.networks:
            self._log("NETWORK", (
                f"PAN:0x{net.pan_id:04X} CH:{net.channel} "
                f"RSSI:{net.rssi}dBm SEC:{net.security} "
                f"Assessment:{net.security_assessment}"
            ))
            if not net.security:
                self._add_finding(
                    "CRITICAL", "Unsecured Zigbee Network",
                    f"PAN 0x{net.pan_id:04X} on channel {net.channel} has no security enabled. "
                    "All traffic is in cleartext. Any device can join and inject commands.",
                    f"Beacon frame shows security=false"
                )
            elif net.security_assessment == "VULNERABLE":
                self._add_finding(
                    "HIGH", "Vulnerable Zigbee Network (Default Key)",
                    f"PAN 0x{net.pan_id:04X} uses default trust center link key. "
                    "Network key can be extracted by sniffing device pairing.",
                    f"Zigbee version: {net.zigbee_version}"
                )
        return self.networks

    # --- Phase 2: Passive Analysis ---
    def phase_analyze(self, channel: int, duration: int = 60) -> list[CapturedPacket]:
        self._log("SNIFF", f"Starting passive capture on channel {channel} for {duration}s")
        self.personality.on_action("sniffing")
        self.client.start_sniff(channel)
        time.sleep(duration)
        self.client.stop_sniff()
        self.packets = self.client.get_packets()
        self._log("SNIFF", f"Captured {len(self.packets)} packets")

        # Check for extracted keys
        self.keys = self.client.get_keys()
        if self.keys:
            for key in self.keys:
                self._add_finding(
                    "CRITICAL", "Network Key Extracted",
                    f"Automatically extracted network key for PAN 0x{key.pan_id:04X} "
                    f"on channel {key.channel} via {key.method}. "
                    "All encrypted traffic on this network can now be decrypted.",
                    f"Key: {key.network_key}"
                )
                self.personality.on_key_extracted()

        # Analyze traffic patterns
        device_addrs = set()
        for pkt in self.packets:
            device_addrs.add(pkt.src_addr)
            device_addrs.add(pkt.dst_addr)
        self._log("ANALYSIS", f"Identified {len(device_addrs)} unique devices")

        return self.packets

    # --- Phase 3: Active Testing (requires authorization) ---
    def phase_test(self, target_network: ZigbeeNetwork):
        if not self.auto_attack:
            self._log("SKIP", "Active testing disabled (auto_attack=False)")
            return

        self._log("TEST", f"Starting active tests on PAN 0x{target_network.pan_id:04X}")
        self.personality.on_action("attacking")

        # Ask Claude what to test
        context = json.dumps({
            "network": {
                "pan_id": hex(target_network.pan_id),
                "channel": target_network.channel,
                "security": target_network.security,
                "assessment": target_network.security_assessment,
                "version": target_network.zigbee_version,
            },
            "packets_captured": len(self.packets),
            "keys_extracted": len(self.keys),
            "devices_found": len(set(p.src_addr for p in self.packets)),
        })
        recommendation = self._ask_claude(
            context,
            "Based on these scan results, what security tests should I run? "
            "List them in order of priority. Only suggest tests appropriate for "
            "the security posture observed."
        )
        self._log("AI", f"Claude recommends: {recommendation[:200]}...")

    # --- Phase 4: Report Generation ---
    def phase_report(self) -> str:
        self._log("REPORT", "Generating security assessment report")
        report = self.reporter.generate(
            networks=self.networks,
            packets=self.packets,
            keys=self.keys,
            findings=self.findings,
            log=self.log,
            session_start=self.session_start,
        )
        report_path = f"/tmp/zigblade_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_path, "w") as f:
            f.write(report)
        self._log("REPORT", f"Report saved to {report_path}")
        return report_path

    # --- Full Auto Assessment ---
    def run_assessment(self, target_channel: Optional[int] = None, duration: int = 120):
        print("\n" + "=" * 60)
        print("  ZigBlade AI — Autonomous IoT Security Assessment")
        print("=" * 60 + "\n")
        self.personality.greet()

        # Phase 1: Discover
        networks = self.phase_discover()
        if not networks:
            self._log("DONE", "No Zigbee networks found in range")
            self.personality.on_empty()
            return

        # Phase 2: Analyze each network
        for net in networks:
            ch = target_channel or net.channel
            self.phase_analyze(ch, duration=min(duration, 60))

        # Phase 3: Test (if authorized)
        for net in networks:
            if net.security_assessment == "VULNERABLE":
                self.phase_test(net)

        # Phase 4: Report
        report_path = self.phase_report()

        # Summary
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        print(f"\n{'=' * 60}")
        print(f"  Assessment Complete")
        print(f"  Networks: {len(networks)} | Packets: {len(self.packets)}")
        print(f"  Keys extracted: {len(self.keys)}")
        print(f"  Findings: {critical} CRITICAL, {high} HIGH")
        print(f"  Report: {report_path}")
        print(f"{'=' * 60}")
        self.personality.on_complete(critical + high)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ZigBlade AI Security Agent")
    parser.add_argument("--url", default="http://192.168.4.1", help="ZigBlade device URL")
    parser.add_argument("--auto", action="store_true", help="Enable active testing")
    parser.add_argument("--channel", type=int, help="Target channel (default: scan all)")
    parser.add_argument("--duration", type=int, default=120, help="Sniff duration per network")
    args = parser.parse_args()

    agent = ZigBladeAgent(device_url=args.url, auto_attack=args.auto)
    agent.run_assessment(target_channel=args.channel, duration=args.duration)
