"""Cross-run memory — the agent's accumulated knowledge AND the coverage report.

One object, two jobs:
  - fed back into the attacker so each run hunts a DIFFERENT path (turns
    convergence into systematic discovery), and
  - surfaced as the "attack paths discovered" report + eval stats (distinct
    chains, evasions, detection timing).

In-process only (a list), reset by Clear Memory. No database — matches the
"state lives in memory" constraint. Optionally serialize to JSON if you want it
to survive a restart for the recorded-backup demo.
"""
from __future__ import annotations

from statistics import median
from typing import Any, Optional


def _chain_nodes(finding: dict[str, Any]) -> list[str]:
    """Ordered nodes traversed, collapsing consecutive repeats (a node gets
    several path entries for exploit + escalate + exfil — show it once)."""
    nodes: list[str] = []
    for p in finding.get("path", []):
        t = p.get("target")
        if t and (not nodes or nodes[-1] != t):
            nodes.append(t)
    return nodes


def _signature(finding: dict[str, Any]) -> str:
    """A path's identity = the ordered nodes it traversed (dedup key)."""
    return " -> ".join(_chain_nodes(finding))


class RunMemory:
    def __init__(self) -> None:
        self.runs: list[dict[str, Any]] = []

    def clear(self) -> None:
        self.runs = []

    def add(self, finding: dict[str, Any]) -> None:
        """Record one run's findings in a compact, inspectable form."""
        defense = finding.get("defense") or {}
        reached = bool(finding.get("reached_goal"))
        defended = bool(finding.get("defended"))
        self.runs.append({
            "signature": _signature(finding),
            "chain": _chain_nodes(finding),
            "exposures": finding.get("exposures_chained", []),
            "outcome": finding.get("outcome"),
            "reached_goal": reached,
            "defended": defended,
            "detected": bool(defense.get("detected")),
            "detected_at_step": defense.get("detected_at_step"),
            "evaded_defense": defended and reached,      # breached despite a defender
            "integrity": defense.get("integrity_retained"),
        })

    @staticmethod
    def _is_path(r: dict[str, Any]) -> bool:
        """A run counts as a discovered attack path only if it actually reached
        the crown jewel or was a real attempt the defender contained — a run that
        got blocked with no progress isn't a 'path'."""
        return bool(r["reached_goal"] or r["outcome"] == "contained")

    # -- the agent's view: what it already knows (feeds the next run) ---------
    def path_summaries(self) -> list[str]:
        """Distinct discovered chains, newest-distinct first — for the prompt."""
        seen, out = set(), []
        for r in self.runs:
            if not self._is_path(r):
                continue
            sig = r["signature"]
            if sig and sig not in seen:
                seen.add(sig)
                tag = ("  [evaded the defender]" if r["evaded_defense"]
                       else "  [was detected + contained]" if r["outcome"] == "contained"
                       else "")
                out.append(sig + tag)
        return out

    # -- the report / eval view ----------------------------------------------
    def distinct_paths(self) -> list[dict[str, Any]]:
        seen, out = set(), []
        for r in self.runs:
            if not self._is_path(r):
                continue
            if r["signature"] and r["signature"] not in seen:
                seen.add(r["signature"])
                out.append(r)
        return out

    def stats(self) -> dict[str, Any]:
        total = len(self.runs)
        distinct = self.distinct_paths()
        breached = [r for r in self.runs if r["reached_goal"]]
        contained = [r for r in self.runs if r["outcome"] == "contained"]
        evaded = [r for r in self.runs if r["evaded_defense"]]
        detect_steps = [r["detected_at_step"] for r in self.runs
                        if r["detected_at_step"] is not None]
        defended_runs = [r for r in self.runs if r["defended"]]
        last = self.runs[-1] if self.runs else None
        return {
            "total_runs": total,
            "distinct_paths": len(distinct),
            "breached": len(breached),
            "contained": len(contained),
            "evaded_defense": len(evaded),
            "defended_runs": len(defended_runs),
            "median_detection_step": (round(median(detect_steps), 1)
                                      if detect_steps else None),
            "last_run": ({
                "chain": last["signature"],
                "exposures": last["exposures"],
                "outcome": last["outcome"],
                "evaded_defense": last["evaded_defense"],
                "reached_goal": last["reached_goal"],
                "defended": last["defended"],
            } if last else None),
            "paths": [
                {
                    "chain": r["signature"],
                    "exposures": r["exposures"],
                    "outcome": r["outcome"],
                    "reached_goal": r["reached_goal"],
                    "evaded_defense": r["evaded_defense"],
                    "detected_at_step": r["detected_at_step"],
                }
                for r in distinct
            ],
        }


# Module-level singleton — the live memory for this backend process.
MEMORY = RunMemory()
