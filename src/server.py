"""
MCP Log Triage Server

Exposes Windows endpoint log analysis as MCP tools, resources, and prompts.
Designed to run locally and connect to a Gemma 4 31B instance over Tailscale.

MCP primitives used:
    Tools     — callable functions (triage_events, explain_technique)
    Resources — readable data (sample event log)
    Prompts   — reusable templates (soc_triage_report)

Author: Ertürk Vural
"""
from __future__ import annotations
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .detections import analyze_event
from .js_loader import analyze_js_loader


mcp = FastMCP("log-triage")

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def triage_events(log_path: str) -> dict:
    """
    Parse a JSON log file of Windows process-creation events and return
    entries flagged by MITRE ATT&CK-mapped detectors.

    Accepts EID 4688 (native Windows audit) or Sysmon EID 1 format.
    Runs two detector families:
        - core: PowerShell, LSASS, shadow delete, obfuscation
        - js_loader: GOOTLOADER-style wscript/cscript abuse

    Args:
        log_path: Absolute path to a JSON file containing an array of
                  events. Each event must have at minimum: Timestamp,
                  Hostname, User, CommandLine.

    Returns:
        dict with total event count, flagged count, and flagged events.
    """
    path = Path(log_path)
    if not path.is_file():
        return {"error": f"File not found: {log_path}"}

    try:
        events = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

    flagged = []
    for event in events:
        # js_loader runs first — more specific patterns
        enriched = analyze_js_loader(event) or analyze_event(event)
        if enriched:
            flagged.append(enriched)

    return {
        "total": len(events),
        "flagged_count": len(flagged),
        "flagged_events": flagged,
    }


@mcp.tool()
def explain_technique(technique_id: str) -> str:
    """
    Return a defender-focused explanation of a MITRE ATT&CK technique
    and the most impactful defensive actions.

    Args:
        technique_id: e.g. 'T1059.001' or 'T1003.001'
    """
    catalog = {
        "T1059.001": (
            "PowerShell abuse (T1059.001): Adversaries use PowerShell for "
            "execution and download. Key defenses: enable ScriptBlock logging "
            "(EID 4104), Module logging, and Constrained Language Mode. "
            "Monitor for -enc, -nop, and IEX patterns in command lines."
        ),
        "T1003.001": (
            "LSASS memory dumping (T1003.001): Extracts credentials from "
            "lsass.exe memory. Defenses: enable Credential Guard, monitor "
            "handle opens to lsass.exe (EID 4663), alert on "
            "comsvcs.dll MiniDump and procdump targeting lsass."
        ),
        "T1490": (
            "Shadow copy deletion (T1490): Ransomware precursor that removes "
            "recovery options. Alert on vssadmin delete shadows, wbadmin delete "
            "catalog, and bcdedit /set recoveryenabled no from any context."
        ),
        "T1027": (
            "Obfuscated payloads (T1027): Encoding hides malicious intent and "
            "evades signature detection. Flag long high-entropy tokens in "
            "command lines. Correlate with parent process anomalies and "
            "PowerShell ScriptBlock logs for decoded content."
        ),
        "T1059.007": (
            "JavaScript via Script Host (T1059.007): GOOTLOADER and CORNFLAKE "
            "delivery pattern. wscript.exe or cscript.exe executes obfuscated "
            "JScript from user-writable paths. Defenses: block script files "
            "from Downloads/Temp via AppLocker or SRP, disable Windows Script "
            "Host where not required, alert on any wscript/cscript to LOLBAS "
            "chain (powershell, certutil, bitsadmin, mshta)."
        ),
    }
    return catalog.get(
        technique_id,
        f"No summary available for {technique_id}. "
        f"Check https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
    )


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("samples://events")
def sample_events() -> str:
    """
    Expose the bundled sample event log as an MCP resource.
    Contains benign and malicious events for testing detection logic.
    """
    sample = SAMPLES_DIR / "sample_events.json"
    if not sample.is_file():
        return "[]"
    return sample.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

@mcp.prompt()
def soc_triage_report(flagged_events_json: str) -> str:
    """
    Structured prompt for converting flagged events into a SOC triage note.
    Designed for Tier-1 analyst handoff or direct LLM consumption.
    """
    return (
        "You are a Tier-1 SOC analyst writing a concise incident triage note. "
        "Given the JSON below, produce:\n\n"
        "1. A one-sentence executive summary.\n"
        "2. A bulleted list of affected hosts and users.\n"
        "3. The most critical MITRE ATT&CK technique observed and why.\n"
        "4. Three concrete next steps for a Tier-2 analyst.\n\n"
        "Rules:\n"
        "- Do not speculate beyond the evidence in the events.\n"
        "- Use MITRE technique IDs where relevant.\n"
        "- Keep the total response under 300 words.\n\n"
        f"Events:\n{flagged_events_json}"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
