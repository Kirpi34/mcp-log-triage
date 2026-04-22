"""
Detection logic mapped to MITRE ATT&CK techniques.
Each detector returns (technique_id, technique_name, confidence) or None.

Author: Ertürk Vural
"""
from __future__ import annotations
import math
import re
from collections import Counter
from typing import Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """
    Approximate Shannon entropy of a string.
    High values (> 4.5) suggest base64 or otherwise encoded payloads.
    Attackers rarely send 'mimikatz' in plain text — they encode it.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

_POWERSHELL_SUSPICIOUS = re.compile(
    r"(?i)(-nop|-noprofile|-enc(odedcommand)?|-w\s*hidden"
    r"|iex\s*\(|downloadstring|downloadfile"
    r"|invoke-expression|from\s*base64)"
)

_LSASS_ACCESS = re.compile(
    r"(?i)(lsass\.exe|comsvcs\.dll.*minidump|procdump.*lsass)"
)

_SHADOW_DELETE = re.compile(
    r"(?i)(vssadmin\s+delete\s+shadows"
    r"|wbadmin\s+delete"
    r"|bcdedit.*recoveryenabled)"
)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_powershell_abuse(cmdline: str) -> Optional[tuple[str, str, str]]:
    """
    T1059.001 — PowerShell
    Flags common execution flags used to bypass logging and download payloads.
    """
    if _POWERSHELL_SUSPICIOUS.search(cmdline):
        return ("T1059.001", "PowerShell", "HIGH")
    return None


def detect_credential_dumping(cmdline: str) -> Optional[tuple[str, str, str]]:
    """
    T1003.001 — LSASS Memory
    Flags attempts to access or dump lsass.exe memory.
    comsvcs.dll MiniDump is a living-off-the-land technique.
    """
    if _LSASS_ACCESS.search(cmdline):
        return ("T1003.001", "LSASS Memory", "CRITICAL")
    return None


def detect_recovery_inhibition(cmdline: str) -> Optional[tuple[str, str, str]]:
    """
    T1490 — Inhibit System Recovery
    Ransomware precursor: deleting shadow copies prevents recovery.
    """
    if _SHADOW_DELETE.search(cmdline):
        return ("T1490", "Inhibit System Recovery", "CRITICAL")
    return None


def detect_obfuscation(cmdline: str) -> Optional[tuple[str, str, str]]:
    """
    T1027 — Obfuscated Files or Information
    Flags command lines containing long high-entropy tokens.
    Legitimate commands rarely have base64 blobs > 40 chars.
    Shannon entropy > 4.5 on a long token = likely encoded payload.
    """
    tokens = [t for t in cmdline.split() if len(t) >= 40]
    for token in tokens:
        if shannon_entropy(token) > 4.5:
            return ("T1027", "Obfuscated Files or Information", "MEDIUM")
    return None


# ---------------------------------------------------------------------------
# Detector pipeline — highest severity first
# ---------------------------------------------------------------------------

DETECTORS = (
    detect_credential_dumping,
    detect_recovery_inhibition,
    detect_powershell_abuse,
    detect_obfuscation,
)


def analyze_event(event: dict) -> Optional[dict]:
    """
    Run a single event through all detectors.
    Returns enriched event dict if any detector fires, else None.
    First match wins (ordered by severity).
    """
    cmdline = event.get("CommandLine", "")
    for detector in DETECTORS:
        result = detector(cmdline)
        if result:
            technique_id, technique_name, confidence = result
            return {
                **event,
                "mitre_technique": technique_id,
                "mitre_name": technique_name,
                "confidence": confidence,
                "detector_family": "core",
            }
    return None
