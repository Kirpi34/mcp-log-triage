# MCP Log Triage Server 🛡️

**A Model Context Protocol (MCP) server that exposes Windows endpoint 
telemetry triage to a locally-hosted AI model — no cloud, no egress.**

![Status](https://img.shields.io/badge/status-active%20development-yellow)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## The Problem

Alert fatigue is real. An analyst reading thousands of raw Event ID 4688 
process-creation logs manually will miss the one PowerShell download cradle 
that actually matters. This project exposes local log triage as an MCP server 
so an AI agent can pre-triage flagged events before a human analyst sees them.

## Architecture
┌─────────────────┐     MCP (stdio)     ┌──────────────────────┐
│  MCP Host       │ ◄─────────────────► │  This Server         │
│  (Gemma 4 31B   │                     │  (FastMCP + Python)  │
│   via Tailscale)│                     └──────────┬───────────┘
└─────────────────┘                                │
┌──────────▼───────────┐
│  Local log files     │
│  (JSON / EID 4688)   │
└──────────────────────┘

## Detection Coverage (MITRE ATT&CK)

| Technique | Name | Signal |
|-----------|------|--------|
| T1059.001 | PowerShell | `-nop`, `-enc`, `IEX`, `DownloadString` |
| T1003.001 | LSASS Memory | `comsvcs.dll MiniDump`, `lsass.exe` access |
| T1490 | Inhibit System Recovery | `vssadmin delete shadows`, `wbadmin delete` |
| T1027 | Obfuscated Files | High-entropy base64 tokens (Shannon scoring) |
| T1059.007 | JavaScript via Script Host | `wscript/cscript` + user-path + LOLBAS chain |

## Stack

- Python 3.10+
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) (`pip install mcp`)
- Gemma 4 31B running locally on RTX 4090
- Tailscale for private network access
- No external API calls — fully offline

## Quick Start

```bash
git clone https://github.com/Kirpi34/mcp-log-triage.git
cd mcp-log-triage
pip install -r requirements.txt
python -m src.server
```

## Project Structure
mcp-log-triage/
├── src/
│   ├── init.py
│   ├── server.py        # FastMCP server — Tools, Resources, Prompts
│   ├── detections.py    # MITRE ATT&CK detection engine
│   └── js_loader.py     # GOOTLOADER-style JS loader detectors
├── samples/
│   └── sample_events.json
├── requirements.txt
└── README.md

## Roadmap

- [x] Project scaffolding and detection engine design
- [x] FastMCP server implementation (Tools/Resources/Prompts)
- [x] Shannon entropy-based obfuscation detector
- [x] GOOTLOADER/CORNFLAKE-style JS loader detection
- [x] Tailscale + Gemma 4 31B integration
- [x] Flare-VM dynamic analysis companion notes

## Author
— 
Built by Ertürk Vural (https://www.linkedin.com/in/ertürk-vural-80b381188) — IT specialist with hands-on experience in Windows administration and endpoint support. This project explores AI-assisted log analysis as a personal interest in detection engineering and Windows internals.
