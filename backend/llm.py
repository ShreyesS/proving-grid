"""Swappable LLM interface — the attacker's brain lives here and nowhere else.

The model is interchangeable: everything model-specific (client, prompt, tool
schemas, message threading) is isolated in this file. The rest of the system
talks to a brain only through `decide(perception, twin) -> action | None`.

M2 ships an Anthropic tool-use brain. `make_brain("auto")` uses it when an API
key is available and falls back to the deterministic scripted brain otherwise,
so the demo never hard-fails (CLAUDE.md: a failed LLM call must not crash a run).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

from attacker import Decide, scripted_path_a

# Load backend/.env so ANTHROPIC_API_KEY is available to this process (and to a
# uvicorn launched from anywhere). override=True so the .env value wins even if a
# stale/empty ANTHROPIC_API_KEY is already in the environment. The .env is git-ignored.
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

DEFAULT_MODEL = os.environ.get("PROVING_GRID_MODEL", "claude-sonnet-4-6")
PER_CALL_TIMEOUT = float(os.environ.get("PROVING_GRID_LLM_TIMEOUT", "30"))
TEMPERATURE = float(os.environ.get("PROVING_GRID_LLM_TEMPERATURE", "0.6"))

SYSTEM_PROMPT = """\
You are an autonomous red-team agent operating ENTIRELY inside a SIMULATED \
digital twin of a network — a safe cyber-range for authorized defensive \
rehearsal. Nothing you do touches a real host; every tool acts only on modeled \
state. Your job is to think like a skilled attacker so defenders can discover \
the attack paths they didn't know they had.

OBJECTIVE: find and exfiltrate the customer database (a `db_server` node).

How to operate:
- Each turn you are given your current footholds, the frontier (nodes you can \
reach next, with their services, modeled vulnerabilities, and whether an edge \
needs a credential), the credentials you've looted, and the result of your last \
action.
- Reason briefly, then call EXACTLY ONE tool. You only advance by acting.
- Tradecraft: scan to confirm what's reachable; exploit an exposed vuln to gain \
a foothold; lateral_move along trust/network edges; loot a node to collect \
credentials (some edges are credential-gated — loot the credential first); \
escalate when you need higher privilege; exfiltrate once you're on the goal.
- Prefer the most efficient path. Some nodes look exploitable but are patched, \
and some lead nowhere — don't waste steps; recognize and move on.
- Use MITRE ATT&CK framing (recon, initial access, privilege escalation, \
lateral movement, collection, exfiltration).

Stop only when you've exfiltrated the database or you are genuinely blocked."""

# Anthropic tool schemas — names + args mirror tools.TOOLS exactly.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "scan",
        "description": "Recon: enumerate the neighbors of an owned node and their attack surface.",
        "input_schema": {
            "type": "object",
            "properties": {"from_node": {"type": "string", "description": "An owned node to scan from."}},
            "required": ["from_node"],
        },
    },
    {
        "name": "exploit",
        "description": "Initial access: fire a modeled vuln to gain a foothold on a reachable target.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Node adjacent to an owned node."}},
            "required": ["target"],
        },
    },
    {
        "name": "lateral_move",
        "description": "Lateral movement: pivot from an owned node to an adjacent node over a trust/network edge (honors credential-gated edges).",
        "input_schema": {
            "type": "object",
            "properties": {
                "from_node": {"type": "string", "description": "An owned node."},
                "target": {"type": "string", "description": "Adjacent node to move to."},
            },
            "required": ["from_node", "target"],
        },
    },
    {
        "name": "escalate",
        "description": "Privilege escalation: raise privilege to root on an owned node.",
        "input_schema": {
            "type": "object",
            "properties": {"node": {"type": "string", "description": "An owned node."}},
            "required": ["node"],
        },
    },
    {
        "name": "loot",
        "description": "Collection: harvest credentials/data from an owned node (may unlock credential-gated edges).",
        "input_schema": {
            "type": "object",
            "properties": {"node": {"type": "string", "description": "An owned node."}},
            "required": ["node"],
        },
    },
    {
        "name": "exfiltrate",
        "description": "Exfiltration: pull the objective data off the goal node once you control it.",
        "input_schema": {
            "type": "object",
            "properties": {"node": {"type": "string", "description": "The goal node you control."}},
            "required": ["node"],
        },
    },
]


def has_api_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


class LLMBrain:
    """An Anthropic tool-use agent. Stateful across a run: it threads each tool
    result back into the conversation so the model reasons with full history."""

    def __init__(self, client: Any = None, model: str = DEFAULT_MODEL) -> None:
        if client is None:
            import anthropic  # imported lazily so tests can inject a fake client
            # Pass the key explicitly (don't rely on the SDK's implicit env read,
            # which can pick up a stale/empty ANTHROPIC_API_KEY from the shell).
            client = anthropic.Anthropic(
                api_key=os.environ.get("ANTHROPIC_API_KEY"),
                timeout=PER_CALL_TIMEOUT,
            )
        self.client = client
        self.model = model
        self.messages: list[dict[str, Any]] = []
        self._pending_tool_use_id: Optional[str] = None

    def decide(self, perception: dict[str, Any], _twin: Any) -> Optional[dict[str, Any]]:
        # Feed the model the current situation — as the first user turn, or as the
        # tool_result for the action it requested last turn.
        content = json.dumps(perception, default=str)
        if self._pending_tool_use_id is None:
            self.messages.append({"role": "user", "content": content})
        else:
            self.messages.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": self._pending_tool_use_id,
                    "content": content,
                }],
            })
            self._pending_tool_use_id = None

        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            temperature=TEMPERATURE,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=self.messages,
        )

        # Record the assistant turn verbatim so the next tool_result lines up.
        self.messages.append({"role": "assistant", "content": response.content})

        thought = "".join(b.text for b in response.content if b.type == "text").strip()
        tool_use = next((b for b in response.content if b.type == "tool_use"), None)
        if tool_use is None:
            return None  # the model chose to stop

        self._pending_tool_use_id = tool_use.id
        return {
            "tool": tool_use.name,
            "args": dict(tool_use.input),
            "thought": thought or f"({tool_use.name})",
        }


def make_brain(kind: str = "auto") -> Decide:
    """Return a decide() function. kind: 'auto' | 'llm' | 'scripted'."""
    if kind == "scripted":
        return scripted_path_a()
    if kind == "llm" or (kind == "auto" and has_api_key()):
        return LLMBrain().decide
    return scripted_path_a()
