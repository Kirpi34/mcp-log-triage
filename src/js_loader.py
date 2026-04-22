"""
JavaScript loader / script-host abuse detectors.

Covers GOOTLOADER-style infection chains where a user double-clicks
a .js or .vbs file delivered inside a ZIP from a compromised site,
and wscript.exe / cscript.exe stages the next payload.

Why this matters:
    GOOTLOADER and CORNFLAKE.V3 (Mandiant) both rely on wscript.exe
    executing heavily obfuscated JScript from user-writable paths.
    Legitimate wscript usage in modern enterprise is rare enough that
    any hit here warrants investigation.

Author: Ertürk Vural
"""
from __future__ import annotations
import re
from typing import Optional

from .detections import shannon_entropy


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# wscript/cscript executing a script file from a user-writable path
_SCRIPT_HOST_USER_PATH = re.compile(
    r"(?i)"
    r"(wscript|cscript)\.exe\s+"
    r".*?"
    r"(\\users\\[^\\]+\\(desktop|downloads|appdata)"
    r"|\\programdata"
    r"|\\windows\\temp"
    r"|\\temp\\)"
    r".*?\.(js|jse|vbs|vbe|wsf)\b"
)

# script host chaining into a LOLBAS binary inline
_LOLBAS_CHAIN = re.compile(
    r"(?i)(wscript|cscript)\.exe.*"
    r"(powershell|cmd\.exe|certutil|bitsadmin|mshta|rundll32)"
)

# minimum length for a suspicious encoded argument
_LONG_ARG_MIN = 300


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_scripthost_from_user_path(
    cmdline: str,
) -> Optional[tuple[str, str, str]]:
    """
    T1059.007 — JavaScript via Script Host
    GOOTLOADER delivery pattern: victim extracts ZIP to Downloads,
    double-clicks .js, wscript runs it from a user-writable path.
    """
    if _SCRIPT_HOST_USER_PATH.search(cmdline):
        return ("T1059.007", "JavaScript (Script Host / user path)", "HIGH")
    return None


def detect_scripthost_long_argument(
    cmdline: str,
) -> Optional[tuple[str, str, str]]:
    """
    T1027 — Obfuscated Script Argument
    GOOTLOADER and CORNFLAKE.V3 pass encoded payloads of several
    hundred characters as arguments. Long + high-entropy = flag.
    """
    if not re.search(r"(?i)(wscript|cscript)\.exe", cmdline):
        return None

    tokens = cmdline.split()
    if not tokens:
        return None

    longest = max(tokens, key=len)
    if len(longest) >= _LONG_ARG_MIN and shannon_entropy(longest) > 4.2:
        return ("T1027", "Obfuscated Script Argument (script host)", "HIGH")
    return None


def detect_scripthost_lolbas_chain(
    cmdline: str,
) -> Optional[tuple[str, str, str]]:
    """
    T1059.007 — Script Host to LOLBAS chain
    Legitimate wscript usage almost never spawns powershell/certutil.
    If it does, something is very wrong.
    """
    if _LOLBAS_CHAIN.search(cmdline):
        return ("T1059.007", "Script Host to LOLBAS chain", "CRITICAL")
    return None


# ---------------------------------------------------------------------------
# Detector pipeline — highest severity first
# ---------------------------------------------------------------------------

JS_LOADER_DETECTORS = (
    detect_scripthost_lolbas_chain,
    detect_scripthost_long_argument,
    detect_scripthost_from_user_path,
)


def analyze_js_loader(event: dict) -> Optional[dict]:
    """
    Run a single event through JS-loader detectors.
    Returns enriched event dict on first match, else None.
    """
    cmdline = event.get("CommandLine", "")
    for detector in JS_LOADER_DETECTORS:
        hit = detector(cmdline)
        if hit:
            technique_id, technique_name, confidence = hit
            return {
                **event,
                "mitre_technique": technique_id,
                "mitre_name": technique_name,
                "confidence": confidence,
                "detector_family": "js_loader",
            }
    return None
