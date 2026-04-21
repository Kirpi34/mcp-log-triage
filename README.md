# MCP Log Triage

A Model Context Protocol (MCP) server that exposes Windows endpoint 
log triage to a locally-hosted AI model.

**Status:** Active development

## Stack
- Python + MCP SDK
- Gemma 4 31B (local, RTX 4090)
- Tailscale (private network)
- MITRE ATT&CK-mapped detectors

## Roadmap
- [ ] Detection engine (PowerShell, LSASS, shadow delete, LNK loaders)
- [ ] FastMCP server with Tools/Resources/Prompts
- [ ] Tailscale + Gemma 4 integration
- [ ] Flare-VM dynamic analysis notes
