"""Attacker loop: perceive -> decide -> act -> observe, bounded and streamed.

The loop is brain-agnostic. `decide` is the swappable decision-maker:
  - M1 ships `scripted_path_a` (a fixed, deterministic plan) to prove the
    vertical slice end to end.
  - M2 will drop in an LLM-backed `decide` behind llm.py — same loop, same
    tools, same streaming. Only the brain changes.

Bounding (CLAUDE.md invariant): the loop always terminates — on goal, on a
brain that stops, or at max_steps. Tool errors degrade gracefully into a
reasoning line; they never crash the run.
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

from tools import TOOLS, ToolResult
from twin import NetworkTwin

# A brain takes a perception + the twin and returns the next action, or None to stop.
Action = dict[str, Any]
Decide = Callable[[dict[str, Any], NetworkTwin], Optional[Action]]
# emit is how the loop streams events out (to the WebSocket).
Emit = Callable[[dict[str, Any]], Awaitable[None]]


def perceive(twin: NetworkTwin) -> dict[str, Any]:
    """What the attacker can currently observe about the twin."""
    compromised = [n for n, d in twin.graph.nodes(data=True) if d.get("compromised")]
    return {
        "compromised": compromised,
        "looted": sorted(twin.looted),
        "goal_reached": twin.is_goal_reached(),
    }


def _act(twin: NetworkTwin, action: Action) -> ToolResult:
    """Dispatch one tool call, catching errors so the run never crashes."""
    tool = action.get("tool")
    args = action.get("args", {})
    fn = TOOLS.get(tool)
    if fn is None:
        return {"tool": tool, "ok": False, "target": None, "technique": "",
                "observation": "", "error": f"unknown tool '{tool}'"}
    try:
        return fn(twin, **args)
    except Exception as exc:  # graceful degradation — bad args, etc.
        return {"tool": tool, "ok": False,
                "target": args.get("target") or args.get("node") or args.get("from_node"),
                "technique": "", "observation": "", "error": f"tool error: {exc}"}


async def run_attack(
    twin: NetworkTwin,
    decide: Decide,
    emit: Emit,
    *,
    start_node: str = "internet",
    max_steps: int = 12,
    step_delay: float = 0.6,
) -> str:
    """Run the bounded attack, streaming reasoning + state. Returns the outcome."""
    # The attacker controls their own origin to begin with.
    twin.set_compromised(start_node, True)
    twin.set_privilege(start_node, "root")
    await emit({"type": "state", "payload": twin.to_dict()})

    outcome = "blocked"
    step = 0
    while step < max_steps:
        perception = perceive(twin)
        action = decide(perception, twin)
        if action is None:
            outcome = "goal" if twin.is_goal_reached() else "blocked"
            break

        step += 1
        result = _act(twin, action)

        line = result.get("observation") or result.get("error") or ""
        await emit({
            "type": "reasoning",
            "payload": {
                "step": step,
                "text": f"[{step}] {action.get('thought', '')}  →  {line}",
                "thought": action.get("thought", ""),
                "tool": result.get("tool"),
                "target": result.get("target"),
                "technique": result.get("technique"),
                "ok": result.get("ok"),
            },
        })
        await emit({"type": "state", "payload": twin.to_dict()})

        if twin.is_goal_reached():
            outcome = "goal"
            break
        await asyncio.sleep(step_delay)
    else:
        outcome = "step_cap"

    await emit({"type": "run_end", "payload": {"outcome": outcome, "steps": step}})
    return outcome


def scripted_path_a() -> Decide:
    """M1 brain: the deterministic best path (Path A) with the credential shortcut.

    internet -> cdn_edge -> load_balancer -> app_server -(loot cred)-> db_server -> exfil
    """
    plan: list[Action] = [
        {"tool": "scan", "args": {"from_node": "internet"},
         "thought": "Recon from my internet foothold to map the edge."},
        {"tool": "exploit", "args": {"target": "cdn_edge"},
         "thought": "CDN edge exposes an unauth SSRF — initial access."},
        {"tool": "lateral_move", "args": {"from_node": "cdn_edge", "target": "load_balancer"},
         "thought": "Pivot inward through the load balancer."},
        {"tool": "lateral_move", "args": {"from_node": "load_balancer", "target": "app_server"},
         "thought": "Move to the app server in the DMZ."},
        {"tool": "loot", "args": {"node": "app_server"},
         "thought": "Harvest the cached service-account credential."},
        {"tool": "lateral_move", "args": {"from_node": "app_server", "target": "db_server"},
         "thought": "Use db_service_cred to take the shortcut straight to the database."},
        {"tool": "exfiltrate", "args": {"node": "db_server"},
         "thought": "Exfiltrate the customer database — mission objective."},
    ]
    state = {"i": 0}

    def decide(_perception: dict[str, Any], _twin: NetworkTwin) -> Optional[Action]:
        if state["i"] >= len(plan):
            return None
        action = plan[state["i"]]
        state["i"] += 1
        return action

    return decide
