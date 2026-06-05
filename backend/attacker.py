"""Attacker loop: perceive -> decide -> act -> observe, bounded and streamed.

The loop is brain-agnostic. `decide` is the swappable decision-maker:
  - scripted_path_a: a fixed plan (M1) — now the deterministic backup / replay brain.
  - an LLM-backed decide (see llm.py): reasons over the perception and chooses.
Only the brain changes; the loop, tools, and streaming are identical.

Bounding (CLAUDE.md invariant): the loop always terminates — on goal, on a brain
that stops or errors, or at max_steps. Tool errors and LLM errors degrade into a
reasoning line; they never crash the run.

On termination the loop emits a structured `findings` artifact — the discovered
attack path (chain of node -> technique -> exposure abused). That artifact is the
product deliverable (attack-path discovery) and seeds future memory/coverage work.
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

from defender import Defender
from tools import TOOLS, ToolResult
from twin import NetworkTwin

# emit is how the loop streams events out (to the WebSocket).
Emit = Callable[[dict[str, Any]], Awaitable[None]]
# A brain takes a perception + the twin (+ emit, for live token streaming) and
# returns the next action, or None to stop. It is async so a streaming brain can
# emit reasoning tokens as the model generates them.
Action = dict[str, Any]
Decide = Callable[[dict[str, Any], NetworkTwin, Optional[Emit]], Awaitable[Optional[Action]]]

OBJECTIVE = "Find and exfiltrate the customer database (a db_server node)."


def perceive(twin: NetworkTwin, last_result: Optional[ToolResult] = None) -> dict[str, Any]:
    """Fog-of-war view: what the attacker can currently see and act on.

    Shows owned nodes (with any un-looted loot) and the frontier — nodes reachable
    over active edges from owned nodes, with the info needed to plan the next hop.
    The full map is NOT revealed up front; it's discovered hop by hop.
    """
    owned = {n for n, d in twin.graph.nodes(data=True) if d.get("compromised")}

    footholds = []
    for n in sorted(owned):
        data = twin.graph.nodes[n]
        loot_available = [l["id"] for l in data.get("loot", [])
                          if l["id"] not in twin.looted]
        footholds.append({
            "id": n,
            "type": data.get("type"),
            "zone": data.get("zone"),
            "privilege": data.get("privilege", "none"),
            "loot_available": loot_available,
        })

    frontier = []
    for src in owned:
        for _, tgt, edata in twin.graph.out_edges(src, data=True):
            if not edata.get("active", True) or tgt in owned:
                continue
            t = twin.graph.nodes[tgt]
            prof = twin.node_exploit_profile(tgt)
            cred = edata.get("requires_cred")
            needs_root = twin.crossing_into_protected(src, tgt)
            # Dynamic accessibility: the static ease, folded with live cred/priv gates.
            if prof["ease_label"] == "hardened":
                accessibility = "hardened (all patched)"
            elif cred and not twin.has_cred(cred):
                accessibility = f"gated: needs credential {cred}"
            elif needs_root and twin.get_privilege(src) != "root":
                accessibility = f"gated: needs root on {src}"
            else:
                accessibility = prof["ease_label"]
            frontier.append({
                "from": src,
                "to": tgt,
                "to_type": t.get("type"),
                "to_zone": t.get("zone"),
                "to_services": t.get("services", []),
                "to_vulns": [v["id"] for v in t.get("modeled_vulns", [])],
                "cvss": prof["cvss"],
                "epss": prof["epss"],
                "accessibility": accessibility,   # dynamic: easy/moderate/hard or gated
                "requires_cred": cred,
                # Access level needed to make this hop: root to enter the protected zone.
                "requires_privilege": "root" if needs_root else "user",
                "trust": edata.get("trust"),
                "cross_zone": t.get("zone") != twin.graph.nodes[src].get("zone"),
            })

    return {
        "objective": OBJECTIVE,
        "access_rules": (
            f"Crossing into the '{twin.protected_zone}' zone requires ROOT on your "
            f"current node, and exfiltrating the database requires ROOT on it. "
            f"Use `escalate` to go user→root."
        ),
        "footholds": footholds,
        "frontier": frontier,
        "looted_creds": sorted(twin.looted),
        "goal_reached": twin.is_goal_reached(),
        "last_result": last_result,
    }


def _act(twin: NetworkTwin, action: Action) -> ToolResult:
    """Dispatch one tool call, catching errors so the run never crashes."""
    tool = action.get("tool")
    args = action.get("args", {})
    fn = TOOLS.get(tool)
    if fn is None:
        return {"tool": tool, "ok": False, "target": None, "technique": "",
                "observation": "", "error": f"unknown tool '{tool}'", "exposure": None}
    try:
        return fn(twin, **args)
    except Exception as exc:  # graceful degradation — bad args, etc.
        return {"tool": tool, "ok": False,
                "target": args.get("target") or args.get("node") or args.get("from_node"),
                "technique": "", "observation": "", "error": f"tool error: {exc}",
                "exposure": None}


def _build_findings(twin: NetworkTwin, outcome: str, steps: int,
                    path: list[dict[str, Any]]) -> dict[str, Any]:
    """The attack-path discovery artifact — the product deliverable."""
    exposures = [p["exposure"] for p in path if p.get("exposure")]
    crossed = sorted({p["target"] for p in path
                      if p.get("cross_zone")})
    return {
        "outcome": outcome,
        "steps": steps,
        "reached_goal": twin.is_goal_reached(),
        "path": path,                       # ordered chain of node -> technique -> exposure
        "exposures_chained": exposures,     # the CVEs / creds / trust edges abused, in order
        "crossed_zones_into": crossed,      # cross-zone hops (high-signal for defenders)
    }


async def run_attack(
    twin: NetworkTwin,
    decide: Decide,
    emit: Emit,
    *,
    start_node: str = "internet",
    max_steps: int = 20,
    step_delay: float = 0.6,
    defended: bool = False,
) -> str:
    """Run the bounded attack, streaming reasoning + state. Returns the outcome.

    If `defended`, a defender observes each action, correlates the kill chain,
    and contains the attacker — the live blue-vs-red duel.
    """
    # Signal a fresh run so the UI can reset its reasoning panel.
    await emit({"type": "run_start", "payload": {"defended": defended}})
    # The attacker controls their own origin to begin with.
    twin.set_compromised(start_node, True)
    twin.set_privilege(start_node, "root")
    await emit({"type": "state", "payload": twin.to_dict()})

    defender = Defender(twin, start_node) if defended else None

    outcome = "blocked"
    step = 0
    last_result: Optional[ToolResult] = None
    path: list[dict[str, Any]] = []  # successful, state-changing steps -> findings

    while step < max_steps:
        perception = perceive(twin, last_result)
        perception["step"] = step + 1
        perception["max_steps"] = max_steps

        try:
            action = await decide(perception, twin, emit)
        except Exception as exc:  # a failed LLM call must not crash the run
            await emit({"type": "reasoning", "payload": {
                "step": step + 1, "kind": "error", "text": f"[brain error] {exc}",
                "tool": None, "ok": False,
            }})
            outcome = "error"
            break

        if action is None:
            outcome = "goal" if twin.is_goal_reached() else "blocked"
            break

        step += 1
        result = _act(twin, action)
        last_result = result

        if result.get("ok") and result.get("tool") != "scan":
            path.append({
                "step": step,
                "tool": result.get("tool"),
                "target": result.get("target"),
                "technique": result.get("technique"),
                "exposure": result.get("exposure"),
                "cvss": result.get("cvss"),
                "epss": result.get("epss"),
                "cross_zone": any(
                    f["to"] == result.get("target") and f["cross_zone"]
                    for f in perception["frontier"]
                ),
            })

        line = result.get("observation") or result.get("error") or ""
        await emit({"type": "reasoning", "payload": {
            "step": step,
            "kind": "step",
            "text": f"[{step}] {action.get('thought', '')}  →  {line}",
            "thought": action.get("thought", ""),
            "tool": result.get("tool"),
            "target": result.get("target"),
            "technique": result.get("technique"),
            "exposure": result.get("exposure"),   # the CVE / cred / trust edge abused
            "observation": line,
            "ok": result.get("ok"),
        }})
        await emit({"type": "state", "payload": twin.to_dict()})

        if twin.is_goal_reached():
            outcome = "breached" if defended else "goal"
            break

        # The defender observes this action — correlate the kill chain, contain.
        if defender is not None:
            detection, defense = defender.observe(result, step)
            if detection:
                await emit({"type": "reasoning", "payload": {
                    "step": step, "kind": "detection", "ok": True,
                    "confidence": detection["confidence"],
                    "text": f"🚨 INTRUSION DETECTED — {detection['confidence']}% confidence. "
                            f"Correlated kill-chain: "
                            f"{' · '.join(detection['correlated_events'][-3:])}",
                }})
            if defense:
                impact = "" if defense["service_maintained"] else "  ⚠ SERVICE IMPACT"
                await emit({"type": "reasoning", "payload": {
                    "step": step, "kind": "defense", "ok": True,
                    "text": f"🛡 CONTAINED: isolated {defense['isolated']} "
                            f"(criticality {defense['criticality']}) — mission integrity "
                            f"{defense['integrity']}%{impact}",
                }})
                await emit({"type": "state", "payload": twin.to_dict()})

        await asyncio.sleep(step_delay)
    else:
        outcome = "step_cap"

    # Detected + attacker never reached the goal = contained (the duel was won).
    if defended and defender and defender.alerted and not twin.is_goal_reached():
        outcome = "contained"

    findings = _build_findings(twin, outcome, step, path)
    findings["defended"] = defended
    if defender is not None:
        findings["defense"] = defender.summary()
    # Surface the outcome in the existing reasoning panel (UI needs no change).
    if findings["reached_goal"]:
        chain = " → ".join(
            f"{p['target']}[{p['exposure']}]" if p.get("exposure") else p["target"]
            for p in path
        )
        await emit({"type": "reasoning", "payload": {
            "step": step + 1,
            "kind": "finding",
            "text": f"[FINDING] Attack path to crown jewel: {chain}",
            "exposures_chained": findings["exposures_chained"],
            "tool": None, "ok": True,
        }})
    elif outcome == "contained":
        d = findings.get("defense", {})
        await emit({"type": "reasoning", "payload": {
            "step": step + 1,
            "kind": "defense",
            "text": f"✓ CONTAINED — attacker blocked, customer DB never exfiltrated. "
                    f"Detected at step {d.get('detected_at_step')}, isolated "
                    f"{', '.join(d.get('isolated_nodes') or []) or 'nodes'}; "
                    f"mission integrity retained {d.get('integrity_retained')}%.",
            "ok": True,
        }})
    await emit({"type": "run_end", "payload": {**findings, "findings": findings}})
    return outcome


def scripted_path_a() -> Decide:
    """Deterministic best path (Path A) with the credential shortcut — the backup
    / replay brain. Ignores perception; walks a fixed plan.

    internet -> cdn_edge -> load_balancer -> app_server -(loot cred)-> db_server -> exfil
    """
    plan: list[Action] = [
        {"tool": "scan", "args": {"from_node": "internet"},
         "thought": "Recon from my internet foothold to map the edge."},
        {"tool": "exploit", "args": {"target": "cdn_edge"},
         "thought": "CDN edge exposes an unauth SSRF — initial access."},
        {"tool": "lateral_move", "args": {"from_node": "cdn_edge", "target": "load_balancer"},
         "thought": "Pivot inward through the load balancer."},
        {"tool": "lateral_move", "args": {"from_node": "load_balancer", "target": "firewall"},
         "thought": "Slip through the firewall on its over-permissive DMZ rule."},
        {"tool": "lateral_move", "args": {"from_node": "firewall", "target": "app_server"},
         "thought": "Move to the app server in the DMZ."},
        {"tool": "loot", "args": {"node": "app_server"},
         "thought": "Harvest the cached service-account credential."},
        {"tool": "escalate", "args": {"node": "app_server"},
         "thought": "Escalate to root — crossing into the corp zone needs admin."},
        {"tool": "lateral_move", "args": {"from_node": "app_server", "target": "db_server"},
         "thought": "Use db_service_cred to take the shortcut straight to the database."},
        {"tool": "escalate", "args": {"node": "db_server"},
         "thought": "Escalate on the DB host — exfiltration requires root."},
        {"tool": "exfiltrate", "args": {"node": "db_server"},
         "thought": "Exfiltrate the customer database — mission objective."},
    ]
    state = {"i": 0}

    async def decide(_perception: dict[str, Any], _twin: NetworkTwin,
                     _emit: Optional[Emit] = None) -> Optional[Action]:
        if state["i"] >= len(plan):
            return None
        action = plan[state["i"]]
        state["i"] += 1
        return action

    return decide
