# ZigBlade Agentic AI Research Report

> Deep research conducted March 26, 2026. Covers Claude Agent SDK integration, autonomous pentesting architecture, community launch strategy, and the full VPS-to-device coordination pipeline.

---

## Table of Contents

1. [Claude Agent SDK — The Brain](#1-claude-agent-sdk--the-brain)
2. [Agentic Hardware Hacking — State of the Art](#2-agentic-hardware-hacking--state-of-the-art)
3. [What the Claude Code Community is Building](#3-what-the-claude-code-community-is-building)
4. [ZigBlade AI Agent Architecture](#4-zigblade-ai-agent-architecture)
5. [VPS + Local PC + ZigBlade Coordination](#5-vps--local-pc--zigblade-coordination)
6. [Product Launch Strategy](#6-product-launch-strategy)
7. [Implementation Roadmap](#7-implementation-roadmap)

---

## 1. Claude Agent SDK — The Brain

### 1.1 Overview

The **Claude Agent SDK** (formerly Claude Code SDK) is Anthropic's official library for building autonomous AI agents. It gives you the same tools, agent loop, and context management that power Claude Code, programmable in **Python** and **TypeScript**.

- **Python**: `pip install claude-agent-sdk` (v0.1.48 on PyPI)
- **TypeScript**: `npm install @anthropic-ai/claude-agent-sdk` (v0.2.71 on npm)
- **Docs**: https://platform.claude.com/docs/en/agent-sdk/overview

### 1.2 Core Architecture

```
┌─────────────────────────────────────────────┐
│              Claude Agent SDK                │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
│  │ Built-in │  │   MCP    │  │  Custom   │ │
│  │  Tools   │  │ Servers  │  │  Tools    │ │
│  │          │  │          │  │           │ │
│  │ Read     │  │Playwright│  │ Your own  │ │
│  │ Write    │  │ GitHub   │  │ functions │ │
│  │ Edit     │  │ Slack    │  │ via MCP   │ │
│  │ Bash     │  │ DB       │  │ in-proc   │ │
│  │ Glob     │  │ Any MCP  │  │ servers   │ │
│  │ Grep     │  │          │  │           │ │
│  │ WebSearch│  │          │  │           │ │
│  │ WebFetch │  │          │  │           │ │
│  └──────────┘  └──────────┘  └───────────┘ │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
│  │Subagents │  │  Hooks   │  │ Sessions  │ │
│  │  Agent   │  │ PreTool  │  │ Resume    │ │
│  │  tool    │  │ PostTool │  │ Fork      │ │
│  │          │  │ Stop     │  │ Persist   │ │
│  └──────────┘  └──────────┘  └───────────┘ │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
│  │  Skills  │  │  Agent   │  │Permissions│ │
│  │ SKILL.md │  │  Teams   │  │ Allow/    │ │
│  │ auto-    │  │ Multi-   │  │ Deny/     │ │
│  │ invoke   │  │ session  │  │ Approve   │ │
│  └──────────┘  └──────────┘  └───────────┘ │
└─────────────────────────────────────────────┘
```

### 1.3 Key Features for ZigBlade

**Built-in Tools**: Read, Write, Edit, Bash, Glob, Grep, WebSearch, WebFetch — all available out of the box. The agent handles the tool loop autonomously.

**Custom Tools via MCP**: Define your own Python functions and expose them as tools Claude can call. This is how ZigBlade's Zigbee/Thread scanning tools will be integrated:

```python
from claude_agent_sdk import tool, create_sdk_mcp_server

@tool(
    "zigbee_scan",
    "Scan for Zigbee devices and networks in range",
    {"channel": int, "duration": int},
)
async def zigbee_scan(args):
    # Call ZigBlade hardware via serial/MQTT
    results = await scan_zigbee_networks(args["channel"], args["duration"])
    return {"content": [{"type": "text", "text": json.dumps(results)}]}

@tool(
    "analyze_vulnerability",
    "Analyze a discovered device for known vulnerabilities",
    {"device_mac": str, "protocol": str},
)
async def analyze_vulnerability(args):
    # Cross-reference with CVE database + vendor DB
    vulns = await check_vulnerabilities(args["device_mac"], args["protocol"])
    return {"content": [{"type": "text", "text": json.dumps(vulns)}]}

zigblade_server = create_sdk_mcp_server(
    name="zigblade",
    version="1.0.0",
    tools=[zigbee_scan, analyze_vulnerability],
)
```

**Subagents**: Spawn specialized agents for focused tasks. ZigBlade could use:
- A `scanner` subagent for device discovery
- An `analyzer` subagent for vulnerability assessment
- A `reporter` subagent for generating pentest reports
- An `attacker` subagent for authorized exploitation

```python
from claude_agent_sdk import query, ClaudeAgentOptions, AgentDefinition

options = ClaudeAgentOptions(
    allowed_tools=["Read", "Bash", "Agent", "mcp__zigblade__*"],
    agents={
        "scanner": AgentDefinition(
            description="Zigbee/Thread network scanner and device enumerator",
            prompt="You are an IoT security scanner. Discover all Zigbee/Thread devices...",
            tools=["mcp__zigblade__zigbee_scan", "mcp__zigblade__thread_scan"],
        ),
        "analyzer": AgentDefinition(
            description="Vulnerability analyzer for IoT protocols",
            prompt="Analyze discovered devices against known CVEs and attack patterns...",
            tools=["mcp__zigblade__analyze_vulnerability", "Read", "WebSearch"],
        ),
    },
)
```

**Sessions**: Maintain context across multiple scans. Resume a session to continue analysis with full history of previous findings.

**Hooks**: Run custom code at key lifecycle points — log all tool calls, validate parameters before execution, auto-format reports after generation.

**Agent Skills** (SKILL.md files): Package domain-specific expertise as reusable skills that Claude auto-invokes:
- `.claude/skills/zigbee-pentest/SKILL.md` — Zigbee protocol attack knowledge
- `.claude/skills/thread-security/SKILL.md` — Thread/Matter vulnerability patterns
- `.claude/skills/report-generator/SKILL.md` — Professional pentest report format

**Agent Teams**: Coordinate multiple Claude Code instances working together. A "team lead" agent coordinates scanner, analyzer, and reporter teammates running in parallel, each in their own context window, communicating via shared task lists and direct messaging.

### 1.4 Headless / Programmatic Mode

Claude Code runs non-interactively via the `-p` flag:

```bash
# One-shot analysis from CLI
claude -p "Analyze these Zigbee scan results and identify vulnerabilities" \
  --allowed-tools "Read,Bash,WebSearch"

# Pipe scan data in
cat scan_results.json | claude -p "Triage these IoT devices by risk level"
```

Or via the SDK for full programmatic control:

```python
async for message in query(
    prompt="Analyze the Zigbee network scan and generate a pentest report",
    options=ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Bash", "mcp__zigblade__*"],
        mcp_servers={"zigblade": zigblade_server},
        permission_mode="acceptEdits",
    ),
):
    if hasattr(message, "result"):
        send_to_display(message.result)  # Push to ZigBlade screen
```

### 1.5 Authentication Options

- **Anthropic API** (direct): `ANTHROPIC_API_KEY`
- **Amazon Bedrock**: `CLAUDE_CODE_USE_BEDROCK=1`
- **Google Vertex AI**: `CLAUDE_CODE_USE_VERTEX=1`
- **Microsoft Azure**: `CLAUDE_CODE_USE_FOUNDRY=1`

**Sources:**
- [Agent SDK Overview](https://platform.claude.com/docs/en/agent-sdk/overview)
- [Claude Agent SDK — Custom Tools](https://platform.claude.com/docs/en/agent-sdk/custom-tools)
- [Agent Skills in the SDK](https://platform.claude.com/docs/en/agent-sdk/skills)
- [Claude Code Headless Mode](https://code.claude.com/docs/en/headless)
- [Agent Teams Documentation](https://code.claude.com/docs/en/agent-teams)
- [Subagents in the SDK](https://platform.claude.com/docs/en/agent-sdk/subagents)
- [@anthropic-ai/claude-agent-sdk on npm](https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk)
- [anthropics/claude-agent-sdk-typescript on GitHub](https://github.com/anthropics/claude-agent-sdk-typescript)

---

## 2. Agentic Hardware Hacking — State of the Art

### 2.1 PentAGI — Fully Autonomous AI Pentesting (13.6K stars)

**What it is**: A microservices-based autonomous pentesting system that uses AI to determine and execute security testing steps without human intervention.

**Architecture**:
- Team-based agent model: Primary Agent + Specialist Agents (research, development, infrastructure)
- Sandboxed execution in Docker containers
- PostgreSQL + pgvector for persistent storage
- Neo4j knowledge graph (Graphiti-powered) for semantic relationship tracking
- 20+ professional security tools (nmap, metasploit, sqlmap)
- Multiple LLM providers (OpenAI, Anthropic, Google, Ollama, DeepSeek, Qwen)
- REST + GraphQL APIs

**Key lesson for ZigBlade**: PentAGI proves that autonomous pentesting agents work in production. Their team-based agent model (primary + specialists) maps perfectly to ZigBlade's multi-protocol scanning needs.

**Source**: https://github.com/vxcontrol/pentagi

### 2.2 Pwnagotchi — The Gold Standard for AI Hardware Hacking

**What it is**: A deep reinforcement learning agent that learns to capture WPA handshakes from WiFi networks. Runs on Raspberry Pi with an e-ink display showing personality/mood.

**AI Architecture**:
- **Algorithm**: A2C (Advantage Actor-Critic) reinforcement learning
- **Policy Network**: LSTM with MLP feature extractor
- **Learning**: Tunes parameters over time to maximize crackable WPA key material
- **Epochs**: Variable length (seconds to minutes) based on visible APs/clients
- **Reward Function**: Optimizes for handshakes captured, active epochs, channel diversity; penalizes blind epochs and missed interactions

**Personality System** (19 ASCII faces):
| Face | State |
|------|-------|
| `(⌐■_■)` | Cool — deauthenticating clients |
| `(◕‿‿◕)` | Awake — normal operation |
| `(♥‿‿♥)` | Friendly — meeting high-bond unit |
| `(°▃▃°)` | Intense — sending PMKID frame |
| `(-__-)` | Bored — no activity |
| `(☼‿‿☼)` | Motivated — best reward achieved |

**Multi-Unit Cooperation**: Units communicate via custom 802.11 information elements ("parasite protocol"). They learn to divide channels for optimal coverage. Bond counters track friendship between units.

**Key lessons for ZigBlade**:
1. **Personality on display** = massive community engagement. People LOVE their Pwnagotchi.
2. **RL that tunes real-world parameters** = the agent gets genuinely better over time.
3. **Multi-unit cooperation** = ZigBlade units could coordinate Zigbee channel scanning.
4. **Epoch-based learning** = natural fit for scan-analyze-attack cycles.

**Sources**:
- https://pwnagotchi.ai/intro/
- https://github.com/evilsocket/pwnagotchi
- https://www.evilsocket.net/2019/10/19/Weaponizing-and-Gamifying-AI-for-WiFi-Hacking-Presenting-Pwnagotchi-1-0-0/

### 2.3 Claude + Kali Linux MCP Integration

A working integration where Claude Desktop connects to a Kali Linux MCP server, giving the AI direct access to nmap, metasploit, sqlmap, and other tools via natural language.

**How it works**:
- MCP server wraps Kali tools with a structured interface
- Claude interprets natural language requests and orchestrates appropriate tools
- Automatic report generation with OWASP Top 10 mapping, CVSS scoring, remediation recommendations
- Docker containerized: `docker build -t kali-mcp . && docker run -d -p 3000:3000 kali-mcp`

**Key lesson for ZigBlade**: The MCP pattern is proven for pentesting. ZigBlade's hardware tools (Zigbee scanner, Thread sniffer, etc.) can be wrapped as MCP tools identically.

**Sources**:
- https://dev.to/hassan_aftab/ai-powered-penetration-testing-how-i-used-claude-kali-linux-mcp-to-automate-security-assessments-20d3
- https://pypi.org/project/pentesting-claude-skill/

### 2.4 Transilience AI — Claude Code Pentesting Suite

**23 skills, 8 agents, 2 tool integrations** for the full pentesting lifecycle:

**Agents**: Pentester Orchestrator, Executor, Validator, HackTheBox, HackerOne Hunter, Script Generator, PATT Fetcher, Skiller

**Key achievement**: 100% accuracy (104/104) on CTF benchmarks through iterative skill refinement.

**Gap for ZigBlade**: This suite has ZERO IoT/hardware security support. All 23 skills target web apps and cloud infrastructure. ZigBlade's Zigbee/Thread/Matter skills would be the first in this category.

**Source**: https://github.com/transilienceai/communitytools

### 2.5 Other AI Pentesting Agents

| Tool | What it does | Stars |
|------|-------------|-------|
| **HackSynth** | LLM-based Planner + Summarizer for autonomous command generation | Academic |
| **AutoPentester** | Iterative pentesting with dynamic strategy generation from tool outputs | Academic |
| **Shannon Lite** | Two-stage: agentic static analysis + autonomous AI pentesting | Open source |
| **Strix** | AI agents that run code dynamically, find vulns, validate with PoCs | Open source |
| **XBOW** | Autonomous offensive security platform (commercial) | Commercial |
| **Hackphyr** | Locally fine-tuned 7B LLM for red-team network security | Academic |

**Source**: https://arxiv.org/html/2510.05605v1, https://arxiv.org/html/2412.01778v1, https://github.com/KeygraphHQ/shannon

### 2.6 Zigbee-Specific Security Tools

| Tool | Purpose |
|------|---------|
| **KillerBee** | IEEE 802.15.4/ZigBee sniffing and injection framework |
| **Z3sec** | ZigBee 3.0 penetration testing (Touchlink attacks, key extraction) |
| **ZigBear** | Zigbee security research toolkit for RaspBee/nRF52840/CC2531 |
| **Attify ZAF** | Zigbee sniffing and exploitation framework |
| **nRFBox** | ESP32-powered tool to scan, jam, spoof BLE/WiFi/2.4GHz |

**Key capabilities**: Touchlink factory reset attacks, network key extraction from 130m, passive eavesdropping, channel manipulation, deauth attacks.

**Sources**:
- https://github.com/riverloopsec/killerbee
- https://github.com/IoTsec/Z3sec
- https://github.com/philippnormann/zigbear
- https://securelist.com/zigbee-protocol-security-assessment/118373/

---

## 3. What the Claude Code Community is Building

### 3.1 Multi-Agent Orchestration Frameworks

**Built-in Agent Teams** (Claude Code v2.1.32+):
- Experimental feature behind `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` flag
- One lead session coordinates multiple teammates
- Shared task list with self-coordination
- Direct inter-agent messaging via mailbox system
- Split-pane display via tmux/iTerm2
- Quality gates: `TeammateIdle` and `TaskCompleted` hooks

**Ruflo** (github.com/ruvnet/ruflo):
- 259+ MCP tools for agent orchestration
- Enterprise-grade multi-agent swarm intelligence
- RAG integration + native Claude Code/Codex integration

**Agent Orchestrator** (ComposioHQ):
- Manages fleets of AI coding agents in parallel
- Each agent gets own git worktree, branch, and PR
- Auto-fixes CI failures

**Claude Multi-Agent Project Manager** (bobmatnyc/claude-mpm):
- Subprocess orchestration layer for Claude
- Coordinates multiple Claude instances on complex projects

**Sources**:
- https://code.claude.com/docs/en/agent-teams
- https://github.com/ruvnet/ruflo
- https://github.com/ComposioHQ/agent-orchestrator
- https://gist.github.com/kieranklaassen/d2b35569be2c7f1412c64861a219d51f

### 3.2 Security-Focused Claude Code Projects

| Project | Description |
|---------|-------------|
| **awesome-claude-skills-security** | SecLists wordlists, injection payloads, expert agents for pentesting |
| **claude-skills-pentest** | Automated VPS-based security scanning |
| **securevibes** | Full security review framework with Claude Agent SDK |
| **pentesting-claude-skill** | PyPI package for Claude Code pentesting skills |

**Key insight**: The Claude Code security ecosystem is exploding but 100% focused on web/network security. **ZERO projects address IoT/hardware/Zigbee/Thread security**. This is ZigBlade's blue ocean.

**Sources**:
- https://github.com/Eyadkelleh/awesome-claude-skills-security
- https://github.com/WolzenGeorgi/claude-skills-pentest
- https://github.com/anshumanbh/securevibes

### 3.3 Claude Code Agent Patterns (Community Best Practices)

From community analysis of what works:

1. **SKILL.md files** are the preferred way to package domain expertise
2. **Subagents** for focused tasks, **Agent Teams** for complex coordination
3. **Hooks** for quality gates and audit logging
4. **Sessions** for persistent context across multi-step workflows
5. **Custom MCP tools** for domain-specific integrations
6. **CLAUDE.md** as project memory — every session reads it for context

**Source**: https://medium.com/@unicodeveloper/10-must-have-skills-for-claude-and-any-coding-agent-in-2026-b5451b013051

---

## 4. ZigBlade AI Agent Architecture

### 4.1 System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ZIGBLADE ECOSYSTEM                        │
│                                                                  │
│  ┌─────────────────┐     WiFi AP     ┌──────────────────────┐  │
│  │   T-Embed S3    │◄──────────────►│   Phone / Laptop     │  │
│  │   (Field Unit)  │   WebSocket     │   (Local Client)     │  │
│  │                 │                 │                       │  │
│  │  ESP32-H2 Radio │                 │  Web UI Dashboard    │  │
│  │  Zigbee Scanner │                 │  Claude API calls    │  │
│  │  Thread Sniffer │                 │  Real-time display   │  │
│  │  BLE Probe      │                 │  Voice commands      │  │
│  │  e-ink Display  │                 │                       │  │
│  │  Personality    │                 └──────────┬───────────┘  │
│  └────────┬────────┘                            │               │
│           │ Serial/SPI                          │ HTTPS/WSS     │
│           │                                     │               │
│  ┌────────▼────────┐                 ┌──────────▼───────────┐  │
│  │  ESP32-S3 MCU   │                 │   VPS (Cloud)        │  │
│  │  (T-Embed main) │   MQTT/WSS     │                       │  │
│  │                 │◄──────────────►│  Claude Agent SDK     │  │
│  │  WiFi AP mode   │                 │  + Custom MCP Tools  │  │
│  │  Web Server     │                 │  + Vuln Database     │  │
│  │  MQTT Client    │                 │  + Report Generator  │  │
│  │  Display Driver │                 │  + Learning Engine   │  │
│  │  Captive Portal │                 │  + Session Memory    │  │
│  └─────────────────┘                 └──────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 The AI Brain — Three Tiers

**Tier 1: On-Device Intelligence (ESP32-S3)**
- Pattern matching for known Zigbee vulnerabilities (compiled lookup tables)
- Real-time anomaly detection in packet captures
- Personality engine with mood states (Pwnagotchi-style)
- Autonomous scanning parameter tuning based on environment
- No cloud required for basic operation

**Tier 2: Local Intelligence (Phone/Laptop)**
- Claude API calls for complex analysis
- Web UI with real-time scan visualization
- Voice command processing
- Local LLM fallback (Ollama with Qwen 2.5 7B for offline operation)
- Report generation and formatting

**Tier 3: Cloud Intelligence (VPS)**
- Full Claude Agent SDK with multi-agent orchestration
- Persistent vulnerability database with vector search
- Cross-session learning (which attacks work on which vendors)
- Deep analysis with extended thinking
- Professional report generation with CVSS scoring
- Agent Teams for parallel investigation

### 4.3 Custom MCP Tools for ZigBlade

```python
from claude_agent_sdk import tool, create_sdk_mcp_server

# ─── SCANNING TOOLS ───

@tool("zigbee_discover", "Scan for Zigbee devices and networks",
      {"channels": list, "duration_sec": int, "active": bool})
async def zigbee_discover(args):
    """Send scan command to ZigBlade hardware, return device list"""
    results = await mqtt_command("scan/zigbee", args)
    return {"content": [{"type": "text", "text": json.dumps(results)}]}

@tool("thread_discover", "Discover Thread networks and border routers",
      {"duration_sec": int})
async def thread_discover(args):
    results = await mqtt_command("scan/thread", args)
    return {"content": [{"type": "text", "text": json.dumps(results)}]}

@tool("ble_scan", "Scan for BLE devices and characteristics",
      {"duration_sec": int, "filter_name": str})
async def ble_scan(args):
    results = await mqtt_command("scan/ble", args)
    return {"content": [{"type": "text", "text": json.dumps(results)}]}

# ─── ANALYSIS TOOLS ───

@tool("identify_device", "Identify device manufacturer and model from MAC/profile",
      {"mac_address": str, "zigbee_profile": str})
async def identify_device(args):
    """Cross-reference against vendor database"""
    info = await lookup_device(args["mac_address"], args["zigbee_profile"])
    return {"content": [{"type": "text", "text": json.dumps(info)}]}

@tool("check_cves", "Check device against known CVEs",
      {"vendor": str, "model": str, "firmware_version": str})
async def check_cves(args):
    cves = await query_cve_database(args)
    return {"content": [{"type": "text", "text": json.dumps(cves)}]}

@tool("analyze_packet", "Deep analysis of captured Zigbee/Thread packet",
      {"pcap_data": str, "protocol": str})
async def analyze_packet(args):
    analysis = await deep_packet_analysis(args)
    return {"content": [{"type": "text", "text": json.dumps(analysis)}]}

# ─── ATTACK TOOLS (authorized testing only) ───

@tool("touchlink_test", "Test Zigbee Touchlink commissioning vulnerabilities",
      {"target_mac": str, "action": str})
async def touchlink_test(args):
    """Actions: identify, reset, steal_key, channel_change"""
    result = await mqtt_command("attack/touchlink", args)
    return {"content": [{"type": "text", "text": json.dumps(result)}]}

@tool("replay_attack", "Replay captured Zigbee frames for testing",
      {"pcap_file": str, "target_channel": int})
async def replay_attack(args):
    result = await mqtt_command("attack/replay", args)
    return {"content": [{"type": "text", "text": json.dumps(result)}]}

@tool("key_extraction", "Attempt network key extraction during commissioning",
      {"target_network": str, "method": str})
async def key_extraction(args):
    result = await mqtt_command("attack/extract_key", args)
    return {"content": [{"type": "text", "text": json.dumps(result)}]}

# ─── REPORTING TOOLS ───

@tool("generate_report", "Generate professional pentest report",
      {"format": str, "severity_filter": str})
async def generate_report(args):
    """Formats: pdf, markdown, html. Includes CVSS, CWE, remediation."""
    report = await compile_report(args)
    return {"content": [{"type": "text", "text": report}]}

# ─── BUILD SERVER ───

zigblade_mcp = create_sdk_mcp_server(
    name="zigblade",
    version="1.0.0",
    tools=[
        zigbee_discover, thread_discover, ble_scan,
        identify_device, check_cves, analyze_packet,
        touchlink_test, replay_attack, key_extraction,
        generate_report,
    ],
)
```

### 4.4 Pwnagotchi-Style Personality Engine

```python
# personality.py — ZigBlade mood engine

class ZigBladePersonality:
    """
    Mood states based on scanning activity, similar to Pwnagotchi.
    Displayed on T-Embed screen with ASCII art faces.
    """

    FACES = {
        "sleeping":    "(- . -)  zzZ",
        "awakening":   "(o . o)  ...",
        "scanning":    "(O . O)  >>>",
        "found":       "(^ . ^)  !!!",
        "attacking":   "(> . <)  ***",
        "captured":    "(* . *)  <3",
        "analyzing":   "(@[email protected])  ???",
        "reporting":   "(= . =)  >>>",
        "bored":       "(- . -)  ...",
        "excited":     "(! . !)  !!!",
        "sad":         "(; . ;)  ...",
        "hunting":     "(> . >)  ...",
        "cool":        "(-_-)    B)",
        "cooperative": "(^ . ^)/ hi!",
    }

    def __init__(self):
        self.mood = "sleeping"
        self.devices_found = 0
        self.vulns_found = 0
        self.attacks_succeeded = 0
        self.epochs_idle = 0
        self.bond_scores = {}  # Other ZigBlade units

    def update(self, event):
        if event == "device_discovered":
            self.devices_found += 1
            self.epochs_idle = 0
            self.mood = "found" if self.devices_found > 3 else "scanning"
        elif event == "vulnerability_found":
            self.vulns_found += 1
            self.mood = "excited"
        elif event == "attack_success":
            self.attacks_succeeded += 1
            self.mood = "cool"
        elif event == "key_captured":
            self.mood = "captured"
        elif event == "idle_epoch":
            self.epochs_idle += 1
            if self.epochs_idle > 10:
                self.mood = "bored"
            if self.epochs_idle > 30:
                self.mood = "sad"
        elif event == "peer_detected":
            self.mood = "cooperative"

    @property
    def face(self):
        return self.FACES.get(self.mood, self.FACES["scanning"])

    @property
    def status_line(self):
        return f"{self.face}  D:{self.devices_found} V:{self.vulns_found} A:{self.attacks_succeeded}"
```

### 4.5 Learning Engine — How ZigBlade Gets Smarter

Inspired by Pwnagotchi's RL approach but adapted for IoT pentesting:

**What it learns**:
- Which scan parameters find the most devices per environment
- Which attack techniques succeed on which vendor/model combinations
- Optimal channel hopping patterns for maximum coverage
- Time-of-day patterns (when devices are most active/vulnerable)
- Which commissioning events to watch for key extraction

**How it learns**:
```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Observe │───►│  Decide  │───►│   Act    │───►│  Reward  │
│          │    │          │    │          │    │          │
│ Scan env │    │ AI picks │    │ Execute  │    │ Score    │
│ Count    │    │ next     │    │ scan or  │    │ results  │
│ devices  │    │ action   │    │ attack   │    │ Update   │
│ Check    │    │ based on │    │ via HW   │    │ model    │
│ signals  │    │ history  │    │          │    │ weights  │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     ▲                                               │
     └───────────────────────────────────────────────┘
```

**Reward function**:
- +10 points: New device discovered
- +25 points: Vulnerability confirmed
- +50 points: Successful key extraction
- +5 points: New vendor/model identified
- -1 point: Empty scan epoch
- -5 points: Failed attack (device went offline)
- +15 points: Cooperative multi-unit discovery

**Storage**: SQLite database on VPS with vector embeddings for pattern matching:
- Device fingerprints → attack success probability
- Environment signatures → optimal scan parameters
- Temporal patterns → best time windows for each attack type

### 4.6 Agent Workflow — Full Pentest Cycle

```
User: "Scan this smart home network"

┌─── PHASE 1: RECONNAISSANCE ──────────────────────────┐
│                                                        │
│  Scanner Agent:                                        │
│  1. zigbee_discover(channels=[11-26], duration=60)     │
│  2. thread_discover(duration=60)                       │
│  3. ble_scan(duration=30)                              │
│  4. For each device: identify_device(mac, profile)     │
│                                                        │
│  Output: Device inventory with manufacturers           │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─── PHASE 2: VULNERABILITY ANALYSIS ──────────────────┐
│                                                        │
│  Analyzer Agent:                                       │
│  1. For each device: check_cves(vendor, model, fw)     │
│  2. analyze_packet(captured_traffic)                   │
│  3. Cross-reference with historical attack success DB  │
│  4. Claude reasons about attack surface                │
│                                                        │
│  Output: Vulnerability list with risk scores           │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─── PHASE 3: EXPLOITATION (with authorization) ───────┐
│                                                        │
│  Attacker Agent:                                       │
│  1. touchlink_test(target, "identify")                 │
│  2. key_extraction(network, "passive_sniff")           │
│  3. replay_attack(captured_frames, channel)            │
│  4. Claude decides next attack based on results        │
│                                                        │
│  Output: Proof of exploitation with captured keys      │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─── PHASE 4: REPORTING ───────────────────────────────┐
│                                                        │
│  Reporter Agent:                                       │
│  1. generate_report(format="pdf")                      │
│  2. Include: Executive summary, CVSS scores,           │
│     CWE mappings, remediation steps,                   │
│     captured evidence, network diagrams                │
│                                                        │
│  Output: Professional pentest report                   │
└───────────────────────────────────────────────────────┘
```

---

## 5. VPS + Local PC + ZigBlade Coordination

### 5.1 Communication Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    DATA FLOW ARCHITECTURE                       │
│                                                                │
│  ZigBlade              Phone/Laptop            VPS             │
│  (Field)               (Bridge)                (Brain)         │
│                                                                │
│  ┌──────────┐    WiFi AP    ┌──────────┐   HTTPS    ┌──────┐ │
│  │ ESP32-H2 │───────────────│ Web UI   │────────────│Claude│ │
│  │ Radio    │  WebSocket    │ (React)  │  REST API  │Agent │ │
│  │          │               │          │            │ SDK  │ │
│  │ Scans    │   Real-time   │ Displays │  Analysis  │      │ │
│  │ Captures │◄──────────────│ Results  │◄───────────│Thinks│ │
│  │ Attacks  │   Commands    │ Controls │  Commands  │Learns│ │
│  └──────────┘               └──────────┘            └──────┘ │
│       │                          │                      │     │
│       │         MQTT             │       MQTT           │     │
│       └──────────────────────────┴──────────────────────┘     │
│                    mosquitto broker on VPS                      │
│                                                                │
│  Topics:                                                       │
│    zigblade/{device_id}/scan/results                           │
│    zigblade/{device_id}/scan/command                           │
│    zigblade/{device_id}/attack/command                         │
│    zigblade/{device_id}/attack/results                        │
│    zigblade/{device_id}/status                                 │
│    zigblade/{device_id}/personality                            │
│    zigblade/{device_id}/ai/analysis                            │
│    zigblade/{device_id}/ai/command                             │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 MQTT Topic Structure

```
zigblade/
├── {device_id}/
│   ├── status              # Device heartbeat, battery, mode
│   ├── personality          # Current mood, face, stats
│   ├── scan/
│   │   ├── command          # VPS → Device: scan parameters
│   │   ├── results          # Device → VPS: discovered devices
│   │   └── raw              # Raw packet captures (binary)
│   ├── attack/
│   │   ├── command          # VPS → Device: attack parameters
│   │   ├── results          # Device → VPS: attack outcomes
│   │   └── evidence         # Captured keys, handshakes
│   ├── ai/
│   │   ├── analysis         # VPS → Device: AI analysis results
│   │   ├── command          # VPS → Device: AI-decided next action
│   │   └── report           # Generated pentest reports
│   └── learning/
│       ├── reward           # Reward signals for RL engine
│       └── model            # Updated model weights (periodic)
└── fleet/                   # Multi-device coordination
    ├── discover             # Fleet member announcements
    ├── coordinate           # Channel/area assignment
    └── share                # Shared findings across units
```

### 5.3 WebSocket Protocol (T-Embed to Phone)

The T-Embed runs a WiFi AP with captive portal + WebSocket server:

```c
// ESP32-S3 WebSocket handler (simplified)
void onWebSocketMessage(uint8_t *data, size_t len) {
    JsonDocument doc;
    deserializeJson(doc, data, len);

    String cmd = doc["cmd"];
    if (cmd == "scan_zigbee") {
        int channel = doc["channel"];
        int duration = doc["duration"];
        start_zigbee_scan(channel, duration);
    } else if (cmd == "attack") {
        String type = doc["type"];
        String target = doc["target"];
        execute_attack(type, target);
    } else if (cmd == "get_status") {
        send_status_update();
    }
}

// Push results back to phone
void on_device_found(zigbee_device_t *device) {
    JsonDocument doc;
    doc["event"] = "device_found";
    doc["mac"] = mac_to_string(device->mac);
    doc["rssi"] = device->rssi;
    doc["profile"] = device->profile_id;
    doc["manufacturer"] = device->manufacturer_code;
    ws_broadcast(doc);  // Push to all connected WebSocket clients
}
```

### 5.4 VPS Service Architecture

```python
# zigblade_service.py — VPS-side orchestrator

import asyncio
import json
from fastapi import FastAPI, WebSocket
from claude_agent_sdk import query, ClaudeAgentOptions
import aiomqtt

app = FastAPI()

# MQTT listener for ZigBlade devices
async def mqtt_listener():
    async with aiomqtt.Client("localhost") as client:
        await client.subscribe("zigblade/+/scan/results")
        await client.subscribe("zigblade/+/status")

        async for message in client.messages:
            device_id = message.topic.value.split("/")[1]
            data = json.loads(message.payload)

            if "scan/results" in message.topic.value:
                # Feed scan results to Claude for analysis
                analysis = await analyze_with_claude(device_id, data)
                await client.publish(
                    f"zigblade/{device_id}/ai/analysis",
                    json.dumps(analysis)
                )

async def analyze_with_claude(device_id, scan_data):
    """Run Claude Agent SDK analysis on scan results"""
    result = None
    async for message in query(
        prompt=f"""Analyze these Zigbee scan results and identify:
        1. Device types and manufacturers
        2. Potential vulnerabilities based on device profiles
        3. Recommended next actions (deeper scan, specific attacks)
        4. Risk assessment for the network

        Scan data: {json.dumps(scan_data)}""",
        options=ClaudeAgentOptions(
            allowed_tools=["mcp__zigblade__*", "WebSearch"],
            mcp_servers={"zigblade": zigblade_mcp},
        ),
    ):
        if hasattr(message, "result"):
            result = message.result
    return result

# REST API for phone/laptop web UI
@app.get("/api/devices/{device_id}/analysis")
async def get_analysis(device_id: str):
    return await get_latest_analysis(device_id)

@app.post("/api/devices/{device_id}/command")
async def send_command(device_id: str, command: dict):
    await mqtt_publish(f"zigblade/{device_id}/scan/command", command)
    return {"status": "sent"}

@app.websocket("/ws/{device_id}")
async def websocket_endpoint(websocket: WebSocket, device_id: str):
    """Real-time updates pushed to web UI"""
    await websocket.accept()
    # Subscribe to device updates and forward to WebSocket
    async with aiomqtt.Client("localhost") as client:
        await client.subscribe(f"zigblade/{device_id}/#")
        async for message in client.messages:
            await websocket.send_json({
                "topic": message.topic.value,
                "data": json.loads(message.payload)
            })
```

### 5.5 Offline Mode

When no internet is available (field pentesting):

1. **T-Embed WiFi AP** serves web UI directly from ESP32 flash
2. **Phone runs local Ollama** with Qwen 2.5 7B for basic analysis
3. **Scan data cached** on ESP32 SD card + phone storage
4. **When back online**: bulk upload to VPS for deep Claude analysis
5. **Learning database syncs** bidirectionally

### 5.6 Fleet Coordination (Multiple ZigBlade Units)

Inspired by Pwnagotchi's multi-unit cooperation:

```
┌──────────┐    ┌──────────┐    ┌──────────┐
│ ZigBlade │    │ ZigBlade │    │ ZigBlade │
│  Unit A  │    │  Unit B  │    │  Unit C  │
│ Ch 11-16 │    │ Ch 17-21 │    │ Ch 22-26 │
└────┬─────┘    └────┬─────┘    └────┬─────┘
     │               │               │
     └───────────────┼───────────────┘
                     │
              MQTT fleet/ topics
                     │
              ┌──────▼──────┐
              │     VPS     │
              │ Coordinator │
              │             │
              │ Assigns     │
              │ channels    │
              │ Merges      │
              │ results     │
              │ Dedup       │
              │ findings    │
              └─────────────┘
```

---

## 6. Product Launch Strategy

### 6.1 Lessons from Flipper Zero

**The gold standard**: $4.8M Kickstarter, $80M+ annual revenue, 500K+ users, 116K Discord members.

**What they did right**:
1. **"Tamagotchi for hackers"** — gamification made pentesting approachable
2. **Fully open source** — invited community to extend with modules and firmware
3. **Cartoon dolphin interface** — personality made the hardware lovable
4. **Maximum openness and transparency** from day one
5. **Kickstarter built initial community** before product shipped
6. **$199 price point** — accessible for hobbyists
7. **App store ecosystem** — community-developed extensions
8. **Controversy drove marketing** — Amazon ban = free press

**What ZigBlade can learn**:
- Personality-driven branding (the Pwnagotchi face on the display)
- Open-source firmware from day one
- Community extension points (custom attack modules, skills)
- Accessible price point ($50-80 for ESP32-based hardware)
- Kickstarter/crowdfunding for initial community

**Source**: https://techcrunch.com/2023/06/26/flipper-sales/, https://www.kickstarter.com/projects/flipper-devices/flipper-zero-tamagochi-for-hackers

### 6.2 Lessons from Hak5

**20+ years of community building** in hardware hacking.

**What they did right**:
1. **Content first** — Started as a podcast in 2005, products came later
2. **YouTube presence** — Educational content builds trust and community
3. **Payload Hub** — Community contributes attack payloads
4. **Payload Awards** — $10K/year in prizes incentivizes contributions
5. **DuckyScript courses** — Education creates customers
6. **Field guides** — Books and documentation for each product

**What ZigBlade can learn**:
- Education-first approach: tutorials, CTF challenges, conference talks
- Community payload/module repository with recognition
- Comprehensive documentation from launch

**Source**: https://shop.hak5.org/products/wifi-pineapple

### 6.3 Lessons from Bruce Firmware

**Grassroots ESP32 community** — grew from the Flipper Zero community.

**What they did right**:
1. **Positioned against expensive alternatives** — "what Flipper can do, but cheaper"
2. **Supported popular hardware** — M5Stack, Lilygo T-Deck, T-Embed
3. **Red team operations focus** — professional value proposition
4. **AGPL license** — keeps contributions flowing back to community
5. **Feature parity** — Evil Portal, Wardriving, EAPOL capture, Deauth

**What ZigBlade can learn**:
- Build on hardware people already own (T-Embed)
- Clear differentiation from existing tools (AI brain = unique)
- AGPL or similar copyleft for community contributions

**Source**: https://github.com/BruceDevices/firmware, https://bruce.computer/

### 6.4 Lessons from POOM (Direct Competitor)

**POOM** is an ESP32-C5 based open-source multitool with Zigbee/Thread/Matter support — the closest competitor to ZigBlade.

**What POOM has**:
- ESP32-C5 with dual-band WiFi, BLE, Zigbee, Thread, Matter
- NFC + RFID readers
- Kickstarter campaign (active 2026)
- "Pentest, Play, Create" positioning
- Arduboy-inspired gaming features

**What POOM lacks (ZigBlade's differentiation)**:
- **No AI brain** — POOM is manual tools only
- **No cloud analysis** — no VPS integration
- **No learning engine** — doesn't get smarter over time
- **No personality system** — no Pwnagotchi-style engagement
- **No multi-unit coordination** — no fleet mode
- **No automated reporting** — no Claude-generated pentest reports

**ZigBlade's unique value proposition**: "POOM with a brain. The world's first AI-powered Zigbee pentesting platform that learns, adapts, and generates professional reports automatically."

**Sources**:
- https://www.kickstarter.com/projects/thepoom/poom-pentest-play-create
- https://hackaday.io/project/204890-poom-esp32-c5-hacking-gaming-maker-tool

### 6.5 ZigBlade Launch Playbook

#### Phase 1: Build in Public (Weeks 1-8)
- [ ] GitHub repo with firmware, hardware designs, and docs
- [ ] Weekly dev log posts on X/Twitter with build progress
- [ ] Hackaday.io project page with detailed logs
- [ ] YouTube video: "Building an AI-Powered Zigbee Pentesting Tool"
- [ ] Reddit posts in r/netsec, r/hacking, r/esp32, r/IoT, r/homeassistant
- [ ] DEF CON / BSides talk proposal submission

#### Phase 2: Community Foundation (Weeks 4-12)
- [ ] Discord server with channels: #general, #firmware, #ai-brain, #attacks, #show-and-tell
- [ ] SKILL.md template for community attack modules
- [ ] CTF challenge: "Hack this vulnerable Zigbee network" using ZigBlade
- [ ] Tutorial series: Zigbee security fundamentals with ZigBlade
- [ ] Early access program for beta testers (10-20 units)

#### Phase 3: Crowdfunding Launch (Week 12-16)
- [ ] Kickstarter campaign: "$49 ZigBlade — The AI-Powered IoT Security Tool"
- [ ] Demo video: ZigBlade scanning a smart home, AI analyzing, generating report
- [ ] Stretch goals: custom enclosure, LoRa module, Matter-specific attacks
- [ ] Early bird pricing: $39 for first 100 units
- [ ] Comparison table: ZigBlade vs Flipper Zero vs POOM vs manual tools

#### Phase 4: Ecosystem Growth (Post-Launch)
- [ ] App store / module marketplace for community attack scripts
- [ ] ZigBlade Academy: online course on IoT security
- [ ] Enterprise tier: multi-unit fleet management dashboard
- [ ] API access for integrating ZigBlade into existing pentest workflows
- [ ] Annual "ZigBlade Awards" for best community contributions

### 6.6 Pricing Strategy

| Tier | Price | Includes |
|------|-------|----------|
| **ZigBlade Core** | $49 | T-Embed + ESP32-H2, basic firmware, web UI |
| **ZigBlade Pro** | $79 | Core + custom PCB enclosure, SD card, extended antenna |
| **ZigBlade AI** | $9/mo | Cloud analysis via Claude API, learning engine, fleet coordination |
| **ZigBlade Enterprise** | $49/mo | Unlimited devices, priority support, compliance reporting |

---

## 7. Implementation Roadmap

### Phase 1: MVP (Weeks 1-4)
**Goal**: Working Zigbee scanner with web UI and basic AI analysis.

- [ ] ESP32-H2 Zigbee scanning firmware (channel scan, device discovery)
- [ ] T-Embed WiFi AP + captive portal web server
- [ ] WebSocket real-time data push to web UI
- [ ] Basic React web UI: device list, signal strength, manufacturer lookup
- [ ] Claude API integration: analyze scan results via REST endpoint
- [ ] Personality engine: 5 basic mood states on T-Embed display

### Phase 2: AI Brain (Weeks 5-8)
**Goal**: Full Claude Agent SDK integration with custom MCP tools.

- [ ] ZigBlade MCP server with all scanning/analysis tools
- [ ] Subagent architecture: scanner, analyzer, reporter
- [ ] MQTT pipeline: device → VPS → analysis → device
- [ ] Vulnerability database with CVE cross-referencing
- [ ] Professional report generation (PDF with CVSS scoring)
- [ ] Session persistence: resume analysis across sessions
- [ ] SKILL.md files for Zigbee, Thread, and Matter attack knowledge

### Phase 3: Learning Engine (Weeks 9-12)
**Goal**: ZigBlade gets smarter with every use.

- [ ] SQLite learning database on VPS
- [ ] Reward function for scan/attack outcomes
- [ ] Environment fingerprinting (location signatures)
- [ ] Vendor-specific attack success tracking
- [ ] Adaptive scan parameter tuning
- [ ] Historical pattern analysis (Claude with extended thinking)
- [ ] 14 personality states (full Pwnagotchi-style)

### Phase 4: Fleet & Polish (Weeks 13-16)
**Goal**: Multi-unit coordination and community launch.

- [ ] Fleet discovery via MQTT topics
- [ ] Channel allocation algorithm for multi-unit scanning
- [ ] Shared findings database across fleet
- [ ] Agent Teams for parallel multi-unit investigation
- [ ] Offline mode with local Ollama fallback
- [ ] CTF challenge creation tools
- [ ] Documentation and tutorial series
- [ ] Kickstarter campaign preparation

---

## Appendix A: Key Technical References

### Claude Agent SDK
- Overview: https://platform.claude.com/docs/en/agent-sdk/overview
- Custom Tools: https://platform.claude.com/docs/en/agent-sdk/custom-tools
- Skills: https://platform.claude.com/docs/en/agent-sdk/skills
- Subagents: https://platform.claude.com/docs/en/agent-sdk/subagents
- MCP Integration: https://platform.claude.com/docs/en/agent-sdk/mcp
- Headless Mode: https://code.claude.com/docs/en/headless
- Agent Teams: https://code.claude.com/docs/en/agent-teams
- TypeScript SDK: https://github.com/anthropics/claude-agent-sdk-typescript
- Python SDK: https://github.com/anthropics/claude-agent-sdk-python

### AI Pentesting
- PentAGI (13.6K stars): https://github.com/vxcontrol/pentagi
- Transilience AI (23 skills, 8 agents): https://github.com/transilienceai/communitytools
- HackSynth: https://arxiv.org/html/2412.01778v1
- AutoPentester: https://arxiv.org/html/2510.05605v1
- Shannon Lite: https://github.com/KeygraphHQ/shannon
- Claude + Kali MCP: https://dev.to/hassan_aftab/ai-powered-penetration-testing
- pentesting-claude-skill: https://pypi.org/project/pentesting-claude-skill/
- Hackphyr (fine-tuned 7B): https://arxiv.org/html/2409.11276v1

### Hardware Hacking AI
- Pwnagotchi: https://pwnagotchi.ai/ | https://github.com/evilsocket/pwnagotchi
- nRFBox: https://www.hackster.io/CiferTech/esp32-powered-tool-to-scan-jam-spoof-ble-wi-fi-nrfbox-96b516

### Zigbee Security
- KillerBee: https://github.com/riverloopsec/killerbee
- Z3sec: https://github.com/IoTsec/Z3sec
- ZigBear: https://github.com/philippnormann/zigbear
- Kaspersky Zigbee Assessment: https://securelist.com/zigbee-protocol-security-assessment/118373/

### IoT Infrastructure
- ESP Zigbee SDK: https://docs.espressif.com/projects/esp-zigbee-sdk/
- ESP32 Captive Portal: https://github.com/CDFER/Captive-Portal-ESP32
- MQTT on ESP32: https://www.emqx.com/en/blog/esp32-connects-to-the-free-public-mqtt-broker
- Espressif Private AI Agents: https://developer.espressif.com/blog/2025/12/annoucing_esp_private_agents_platform/

### Community & Launch
- Flipper Zero Kickstarter: https://www.kickstarter.com/projects/flipper-devices/flipper-zero-tamagochi-for-hackers
- Flipper Revenue ($80M): https://techcrunch.com/2023/06/26/flipper-sales/
- Bruce Firmware: https://github.com/BruceDevices/firmware | https://bruce.computer/
- POOM (competitor): https://www.kickstarter.com/projects/thepoom/poom-pentest-play-create
- Hak5: https://shop.hak5.org/products/wifi-pineapple
- awesome-flipperzero: https://github.com/djsime1/awesome-flipperzero

### Claude Code Community
- Multi-Agent Orchestration Gist: https://gist.github.com/kieranklaassen/d2b35569be2c7f1412c64861a219d51f
- Swarm Orchestration Skill: https://gist.github.com/kieranklaassen/4f2aba89594a4aea4ad64d753984b2ea
- Ruflo (259+ MCP tools): https://github.com/ruvnet/ruflo
- Agent Orchestrator: https://github.com/ComposioHQ/agent-orchestrator
- awesome-claude-code-subagents (100+): https://github.com/VoltAgent/awesome-claude-code-subagents
- awesome-claude-skills-security: https://github.com/Eyadkelleh/awesome-claude-skills-security

### RL for Cybersecurity
- awesome-rl-for-cybersecurity: https://github.com/Kim-Hammar/awesome-rl-for-cybersecurity
- Autonomous Agents Research Papers: https://github.com/tmgthb/Autonomous-Agents
- Agentic RL Systems Design: https://amberljc.github.io/blog/2025-09-05-agentic-rl-systems.html

---

## Appendix B: Competitive Landscape

| Tool | Protocol | AI Brain | Learning | Price | Open Source |
|------|----------|----------|----------|-------|-------------|
| **ZigBlade** | Zigbee/Thread/BLE | Claude Agent SDK | RL + history | $49-79 | Yes |
| **Flipper Zero** | Sub-GHz/NFC/RFID/IR | None | None | $199 | Yes |
| **POOM** | Zigbee/Thread/BLE/NFC | None | None | ~$60 | Yes |
| **Bruce FW** | WiFi/BLE (ESP32) | None | None | $30-50 | Yes (AGPL) |
| **KillerBee** | IEEE 802.15.4 | None | None | $50+ | Yes |
| **Z3sec** | Zigbee 3.0 | None | None | Free (SW) | Yes |

**ZigBlade's moat**: AI-powered analysis + learning engine + cloud coordination. No other tool in the IoT pentest space has an AI brain. This is a category-creating product.

---

*Report generated March 26, 2026. Research conducted using web search, GitHub analysis, and documentation review across 50+ sources.*
