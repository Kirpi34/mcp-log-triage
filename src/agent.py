"""
MCP Log Triage Agent

Bridges the MCP detection server with a locally-hosted LLM (Gemma 4 31B
via LM Studio) to produce SOC-ready triage reports.

Flow:
    1. Spawn MCP server as subprocess (stdio transport)
    2. Call triage_events tool with given log path
    3. Collect flagged events
    4. Send flagged events to Gemma via OpenAI-compatible API
    5. Gemma returns a natural-language SOC triage report

Usage:
    python -m src.agent <path-to-log.json>

Author: Erturk Vural
"""
from __future__ import annotations
import asyncio
import json
import sys
from pathlib import Path

from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


LM_STUDIO_URL = "http://localhost:1234/v1"
MODEL_NAME = "gemma-4-31b-it-abliterated"
REQUEST_TIMEOUT = 600


SYSTEM_PROMPT = """You are a Tier-1 SOC analyst writing a concise incident
triage note for a Tier-2 colleague. You will receive a JSON list of
Windows process-creation events that were flagged by MITRE ATT&CK-mapped
detectors. Produce:

1. A one-sentence executive summary.
2. A bulleted list of affected hosts and users.
3. The single most critical MITRE technique observed and why it matters.
4. Three concrete next steps for Tier-2 investigation.

Rules:
- Do not speculate beyond the evidence.
- Use MITRE technique IDs where relevant.
- Keep the total response under 300 words.
- Write in professional English, no marketing tone.
"""


async def run_triage(log_path: str) -> dict:
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "src.server"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "triage_events",
                arguments={"log_path": log_path},
            )

    if result.structuredContent:
        return result.structuredContent
    if result.content and hasattr(result.content[0], "text"):
        return json.loads(result.content[0].text)
    return {"error": "Empty response from MCP server"}


def ask_gemma(flagged_events: list) -> str:
    client = OpenAI(
        base_url=LM_STUDIO_URL,
        api_key="not-needed",
        timeout=REQUEST_TIMEOUT,
    )

    payload = json.dumps(flagged_events, indent=2)
    user_message = (
        f"Here are the flagged events. Produce the triage note.\n\n"
        f"```json\n{payload}\n```"
    )

    print("[*] Sending flagged events to Gemma 4 31B...", flush=True)

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m src.agent <path-to-log.json>")
        return 1

    log_path = str(Path(sys.argv[1]).resolve())
    print(f"[*] Running MCP triage on: {log_path}")

    triage = asyncio.run(run_triage(log_path))

    if "error" in triage:
        print(f"[-] MCP error: {triage['error']}")
        return 1

    total = triage.get("total", 0)
    flagged_count = triage.get("flagged_count", 0)
    flagged_events = triage.get("flagged_events", [])

    print(f"[*] MCP triage complete: {flagged_count}/{total} events flagged.")

    if not flagged_events:
        print("[+] No suspicious activity detected.")
        return 0

    print()
    report = ask_gemma(flagged_events)

    print("=" * 72)
    print("SOC TRIAGE REPORT (Gemma 4 31B, local inference)")
    print("=" * 72)
    print()
    print(report)
    print()
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
