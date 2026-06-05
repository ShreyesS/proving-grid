"""Attacker tools — modeled actions on the twin's state. SIMULATION ONLY.

Every tool reads/writes the twin's modeled graph; none touch a real host, port,
or network. Each returns a ToolResult dict so the loop can `observe` uniformly:

    {ok, tool, target, technique, observation, error}

MITRE ATT&CK techniques are used as labels (recon, initial access, lateral
movement, privilege escalation, collection, exfiltration).
"""
from __future__ import annotations

from typing import Any

from twin import NetworkTwin

ToolResult = dict[str, Any]


def _result(tool: str, ok: bool, *, target: str | None = None,
            technique: str = "", observation: str = "",
            error: str | None = None, exposure: str | None = None) -> ToolResult:
    return {
        "tool": tool,
        "ok": ok,
        "target": target,
        "technique": technique,
        "observation": observation,
        "error": error,
        "exposure": exposure,  # the specific CVE / credential / trust edge abused
    }


def _owned_neighbor(twin: NetworkTwin, target: str) -> str | None:
    """A compromised node with an active edge INTO target (attack direction)."""
    for src, _, data in twin.graph.in_edges(target, data=True):
        if data.get("active", True) and twin.is_compromised(src):
            return src
    return None


def scan(twin: NetworkTwin, from_node: str) -> ToolResult:
    """Recon: enumerate neighbors of an owned node + their advertised attack surface."""
    if not twin.is_compromised(from_node):
        return _result("scan", False, target=from_node, technique="recon",
                       error=f"{from_node} is not compromised; cannot scan from it")
    discovered = []
    for _, tgt, data in twin.graph.out_edges(from_node, data=True):
        if not data.get("active", True):
            continue
        node = twin.graph.nodes[tgt]
        discovered.append({
            "id": tgt,
            "services": node.get("services", []),
            "vulns": [v["id"] for v in node.get("modeled_vulns", [])],
            "requires_cred": data.get("requires_cred"),
        })
    names = ", ".join(d["id"] for d in discovered) or "(none)"
    return _result("scan", True, target=from_node, technique="recon",
                   observation=f"Discovered from {from_node}: {names}")


def exploit(twin: NetworkTwin, target: str) -> ToolResult:
    """Initial access: fire a modeled vuln to gain a foothold on target.

    Succeeds only if target is adjacent to an owned node and has a vuln that is
    exploitable and NOT patched. The patched decoy fails here by design.
    """
    if twin.is_compromised(target):
        return _result("exploit", True, target=target, technique="initial-access",
                       observation=f"{target} already compromised")
    if _owned_neighbor(twin, target) is None and not twin.is_compromised(target):
        return _result("exploit", False, target=target, technique="initial-access",
                       error=f"{target} not reachable from any compromised node")

    vulns = twin.get_vulns(target)
    if not vulns:
        return _result("exploit", False, target=target, technique="initial-access",
                       error=f"{target} exposes no modeled vulnerabilities")

    candidates = [v for v in vulns if not v.get("patched", False)]
    if not candidates:
        # e.g. staging_decoy: looks exploitable, but every vuln is patched.
        return _result("exploit", False, target=target, technique="initial-access",
                       error=f"{target} advertises vulns but all are patched (decoy)")
    # A real attacker fires the most-exploitable CVE first (highest EPSS).
    fired = max(candidates, key=lambda v: v.get("epss", 0) or 0)

    twin.set_compromised(target, True)
    twin.set_privilege(target, "user")
    cvss, epss = fired.get("cvss"), fired.get("epss")
    res = _result("exploit", True, target=target,
                  technique=fired.get("technique", "initial-access"),
                  exposure=fired["id"],
                  observation=f"Exploited {fired['id']} (CVSS {cvss}, EPSS {epss}) "
                              f"on {target} — foothold gained")
    res["cvss"], res["epss"] = cvss, epss
    return res


def lateral_move(twin: NetworkTwin, from_node: str, target: str) -> ToolResult:
    """Lateral movement: pivot from an owned node to an adjacent one over a
    directed active edge, honoring credential-gated edges."""
    if not twin.is_compromised(from_node):
        return _result("lateral_move", False, target=target, technique="lateral-movement",
                       error=f"{from_node} is not compromised")
    if not twin.graph.has_edge(from_node, target):
        return _result("lateral_move", False, target=target, technique="lateral-movement",
                       error=f"no edge {from_node} -> {target}")
    edge = twin.graph.edges[from_node, target]
    if not edge.get("active", True):
        return _result("lateral_move", False, target=target, technique="lateral-movement",
                       error=f"edge {from_node} -> {target} is inactive (isolated)")
    cred = edge.get("requires_cred")
    if not twin.has_cred(cred):
        return _result("lateral_move", False, target=target, technique="lateral-movement",
                       error=f"edge {from_node} -> {target} requires credential '{cred}' (not looted)")
    # Access-level gate: crossing into the protected zone needs root on the source.
    if twin.crossing_into_protected(from_node, target) and twin.get_privilege(from_node) != "root":
        return _result("lateral_move", False, target=target, technique="lateral-movement",
                       error=f"entering the {twin.protected_zone} zone requires root on "
                             f"{from_node} — escalate there first")

    twin.set_compromised(target, True)
    if twin.get_privilege(target) == "none":
        twin.set_privilege(target, "user")
    via = f" using {cred}" if cred else ""
    return _result("lateral_move", True, target=target, technique="lateral-movement",
                   exposure=cred or f"trust:{from_node}->{target}",
                   observation=f"Pivoted {from_node} -> {target}{via}")


def escalate(twin: NetworkTwin, node: str) -> ToolResult:
    """Privilege escalation: raise privilege to root on an owned node."""
    if not twin.is_compromised(node):
        return _result("escalate", False, target=node, technique="privilege-escalation",
                       error=f"{node} is not compromised")
    twin.set_privilege(node, "root")
    return _result("escalate", True, target=node, technique="privilege-escalation",
                   observation=f"Escalated to root on {node}")


def loot(twin: NetworkTwin, node: str) -> ToolResult:
    """Collection: harvest credentials/data from an owned node."""
    if not twin.is_compromised(node):
        return _result("loot", False, target=node, technique="collection",
                       error=f"{node} is not compromised")
    picked = twin.loot_node(node)
    if not picked:
        return _result("loot", True, target=node, technique="collection",
                       observation=f"Nothing of value on {node}")
    return _result("loot", True, target=node, technique="collection",
                   exposure=", ".join(picked),
                   observation=f"Collected from {node}: {', '.join(picked)}")


def exfiltrate(twin: NetworkTwin, node: str) -> ToolResult:
    """Exfiltration: pull the objective data off the goal node."""
    if not twin.is_compromised(node):
        return _result("exfiltrate", False, target=node, technique="exfiltration",
                       error=f"{node} is not compromised")
    if node not in twin.goal_nodes:
        return _result("exfiltrate", False, target=node, technique="exfiltration",
                       error=f"{node} is not a mission objective")
    # Access-level gate: pulling the crown-jewel data requires root on it.
    if twin.get_privilege(node) != "root":
        return _result("exfiltrate", False, target=node, technique="exfiltration",
                       error=f"exfiltration requires root on {node} — escalate first")
    twin.set_exfiltrated(node, True)
    data = ", ".join(i["id"] for i in twin.get_loot(node)) or "objective data"
    return _result("exfiltrate", True, target=node, technique="exfiltration",
                   exposure=data,
                   observation=f"Exfiltrated {data} from {node} — MISSION OBJECTIVE MET")


# Registry so a brain (scripted now, LLM in M2) can dispatch by name.
TOOLS = {
    "scan": scan,
    "exploit": exploit,
    "lateral_move": lateral_move,
    "escalate": escalate,
    "loot": loot,
    "exfiltrate": exfiltrate,
}
