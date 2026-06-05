"""Defender: rule-based correlation detection + costed containment.

Watches the attacker's actions on the twin and plays the real security game —
not "lower the per-exploit probability" (a determined attacker with infinite
quiet tries always wins that), but DETECT-BEFORE-GOAL: correlate the kill chain
into one high-confidence verdict, then contain the foothold so the attempts
stop. Containment is a costed tradeoff — isolating a node takes its service
down, so mission_integrity reflects the price of defending.

Behind the same swappable-brain pattern as the attacker (llm.py): the response
policy lives in one place, so an LLM blue-teamer can replace it later. Today it
is deterministic rules — reliable on stage.
"""
from __future__ import annotations

from typing import Any, Optional

from twin import NetworkTwin

# Suspicion accrues only on MONITORED nodes (a path through unmonitored hosts is
# stealthier — that becomes a finding). Deeper zones = stronger signal.
_ZONE_DEPTH = {"external": 0, "edge": 1, "dmz": 2, "corp": 3}
THRESHOLD = 35            # fire once correlated suspicion crosses this...
MIN_TECHNIQUES = 2        # ...AND at least two distinct ATT&CK techniques are seen
ESCALATE_WEIGHT = 15
SCAN_WEIGHT = 8


class Defender:
    """Rule-based correlation detector + containment policy."""

    def __init__(self, twin: NetworkTwin, entry: str) -> None:
        self.twin = twin
        self.entry = entry
        self.suspicion = 0
        self.techniques: set[str] = set()
        self.events: list[str] = []   # the correlated signals behind a verdict
        self.alerted = False
        self.detected_at: Optional[int] = None
        self.isolated: list[str] = []

    # -- detection -----------------------------------------------------------
    def _suspicion_for(self, result: dict[str, Any]) -> tuple[int, Optional[str]]:
        tool = result.get("tool")
        if tool == "exfiltrate":
            return 100, "exfiltration attempt on the crown jewel"
        target = result.get("target")
        if not target or not self.twin.node_exists(target):
            return 0, None
        if not self.twin.graph.nodes[target].get("defender_monitor"):
            return 0, None  # no sensor here — stealthy
        if tool in ("exploit", "lateral_move"):
            zone = self.twin.node_zone(target)
            return _ZONE_DEPTH.get(zone, 1) * 12, f"{tool} on {target} ({zone})"
        if tool == "escalate":
            return ESCALATE_WEIGHT, f"privilege escalation on {target}"
        if tool == "scan":
            return SCAN_WEIGHT, f"recon from {target}"
        return 0, None

    def observe(self, result: dict[str, Any], step: int
                ) -> tuple[Optional[dict], Optional[dict]]:
        """Process one attacker action. Returns (detection?, containment?)."""
        if not result.get("ok"):
            return None, None

        add, label = self._suspicion_for(result)
        if add:
            self.suspicion += add
            if result.get("technique"):
                self.techniques.add(result["technique"])
            if label:
                self.events.append(label)

        detection = None
        if (not self.alerted and self.suspicion >= THRESHOLD
                and len(self.techniques) >= MIN_TECHNIQUES):
            self.alerted = True
            self.detected_at = step
            detection = {
                "confidence": min(99, self.suspicion),
                "verdict": "high-confidence intrusion",
                "correlated_events": list(self.events),
                "detected_at_step": step,
            }

        # Once alerted, shadow the attacker: isolate each fresh foothold.
        defense = None
        if self.alerted and result.get("tool") in ("exploit", "lateral_move"):
            defense = self._contain(result.get("target"))
        return detection, defense

    # -- response ------------------------------------------------------------
    def _contain(self, node: Optional[str]) -> Optional[dict]:
        """Isolate a compromised node — but never the crown jewel (that IS the
        service we protect) or the attacker's external origin."""
        if (not node or node in self.twin.goal_nodes or node == self.entry
                or self.twin.is_isolated(node)):
            return None
        self.twin.set_isolated(node)
        self.isolated.append(node)
        goal = next(iter(self.twin.goal_nodes), None)
        # Is the protected service still reachable for legitimate traffic?
        service_ok = self.twin.has_route(self.entry, goal) if goal else True
        return {
            "isolated": node,
            "criticality": self.twin.graph.nodes[node].get("criticality", 0),
            "service_maintained": service_ok,
            "integrity": self.twin.get_mission_integrity(),
        }

    def summary(self) -> dict[str, Any]:
        return {
            "detected": self.alerted,
            "detected_at_step": self.detected_at,
            "confidence": min(99, self.suspicion) if self.alerted else 0,
            "isolated_nodes": list(self.isolated),
            "integrity_retained": self.twin.get_mission_integrity(),
        }
