"""
ZigBlade MCP Server — Control ZigBlade hardware from Claude Code.

Add to your Claude Code settings:
{
    "mcpServers": {
        "zigblade": {
            "command": "python3",
            "args": ["/root/zigblade/agent/zigblade_mcp_server.py"]
        }
    }
}

Then Claude Code can use tools like:
- zigblade_scan — scan for Zigbee networks
- zigblade_sniff — capture packets on a channel
- zigblade_keys — get extracted encryption keys
- zigblade_status — device status
- zigblade_attack — run security tests
"""
import json
import sys
from typing import Any
from zigblade_client import ZigBladeClient

# MCP Protocol implementation (stdin/stdout JSON-RPC)
client = ZigBladeClient(base_url="http://192.168.4.1")


def send_response(id: Any, result: Any):
    response = {"jsonrpc": "2.0", "id": id, "result": result}
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def send_error(id: Any, code: int, message: str):
    response = {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


TOOLS = [
    {
        "name": "zigblade_status",
        "description": "Get ZigBlade device status (connected, channel, packet count, battery)",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "zigblade_scan",
        "description": "Scan for Zigbee networks on all 16 channels. Returns list of networks with PAN ID, channel, coordinator address, RSSI, security assessment (VULNERABLE/HARDENED/UNKNOWN).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {
                    "type": "integer",
                    "description": "Specific channel 11-26, or omit for all channels",
                },
            },
        },
    },
    {
        "name": "zigblade_sniff",
        "description": "Start or stop packet capture on a Zigbee channel. Auto-decrypts if key is known. Auto-extracts network keys from pairing events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop"],
                    "description": "Start or stop sniffing",
                },
                "channel": {
                    "type": "integer",
                    "description": "Channel to sniff (11-26)",
                },
                "key": {
                    "type": "string",
                    "description": "Optional: 32-char hex network key for decryption",
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "zigblade_packets",
        "description": "Get captured packets from the sniffer. Returns decoded packet info: frame type, source/dest addresses, PAN ID, RSSI, payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max packets to return (default 20)",
                },
            },
        },
    },
    {
        "name": "zigblade_keys",
        "description": "Get all extracted network encryption keys. These are captured automatically during device pairing events.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "zigblade_attack",
        "description": "Run a security test against a Zigbee network. AUTHORIZED TESTING ONLY. Types: replay (replay captured packet), touchlink (touchlink commissioning test), disassoc (disassociation test), beacon_flood (beacon flooding), fuzz (ZCL fuzzing).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["replay", "touchlink", "disassoc", "beacon_flood", "fuzz"],
                    "description": "Attack type",
                },
                "target": {
                    "type": "string",
                    "description": "Target address (hex) or packet index for replay",
                },
            },
            "required": ["type"],
        },
    },
    {
        "name": "zigblade_set_channel",
        "description": "Set the active Zigbee channel (11-26)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "integer", "description": "Channel 11-26"},
            },
            "required": ["channel"],
        },
    },
]


def handle_tool_call(name: str, arguments: dict) -> str:
    try:
        if name == "zigblade_status":
            result = client.get_status()
            return json.dumps(result, indent=2)

        elif name == "zigblade_scan":
            ch = arguments.get("channel")
            networks = client.scan_and_wait(timeout=30)
            return json.dumps(
                [
                    {
                        "pan_id": hex(n.pan_id),
                        "channel": n.channel,
                        "coordinator": n.coordinator,
                        "rssi": n.rssi,
                        "security": n.security,
                        "assessment": n.security_assessment,
                    }
                    for n in networks
                ],
                indent=2,
            )

        elif name == "zigblade_sniff":
            action = arguments["action"]
            if action == "start":
                ch = arguments.get("channel", 15)
                key = arguments.get("key")
                result = client.start_sniff(ch, key)
                return f"Sniffer started on channel {ch}"
            else:
                client.stop_sniff()
                return "Sniffer stopped"

        elif name == "zigblade_packets":
            limit = arguments.get("limit", 20)
            packets = client.get_packets()[:limit]
            return json.dumps(
                [
                    {
                        "type": p.frame_type,
                        "src": p.src_addr,
                        "dst": p.dst_addr,
                        "pan_id": hex(p.pan_id),
                        "rssi": p.rssi,
                        "channel": p.channel,
                        "payload": p.payload_hex[:64],
                    }
                    for p in packets
                ],
                indent=2,
            )

        elif name == "zigblade_keys":
            keys = client.get_keys()
            return json.dumps(
                [
                    {
                        "key": k.network_key,
                        "pan_id": hex(k.pan_id),
                        "channel": k.channel,
                        "method": k.method,
                    }
                    for k in keys
                ],
                indent=2,
            )

        elif name == "zigblade_attack":
            attack_type = arguments["type"]
            target = arguments.get("target")
            if attack_type == "replay":
                result = client.attack_replay(int(target))
            elif attack_type == "touchlink":
                result = client.attack_touchlink(target)
            elif attack_type == "disassoc":
                result = client.attack_disassoc(target)
            elif attack_type == "beacon_flood":
                result = client.attack_beacon_flood(int(target, 16))
            elif attack_type == "fuzz":
                result = client.attack_fuzz(target)
            else:
                return f"Unknown attack type: {attack_type}"
            return json.dumps(result, indent=2)

        elif name == "zigblade_set_channel":
            ch = arguments["channel"]
            result = client.set_channel(ch)
            return f"Channel set to {ch}"

        else:
            return f"Unknown tool: {name}"

    except Exception as e:
        return f"Error: {e}"


def main():
    """MCP stdio server main loop."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            send_response(id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "zigblade", "version": "0.1.0"},
            })

        elif method == "tools/list":
            send_response(id, {"tools": TOOLS})

        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            result = handle_tool_call(name, arguments)
            send_response(id, {
                "content": [{"type": "text", "text": result}],
            })

        elif method == "notifications/initialized":
            pass  # Client notification, no response needed

        else:
            send_error(id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
