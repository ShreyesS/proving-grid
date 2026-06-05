"""Digital twin: load topology.yaml into a networkx graph and expose modeled state queries."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import networkx as nx
import yaml

DEFAULT_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent / "topology.yaml"


class NetworkTwin:
    """In-memory simulation graph; all compromise/isolation state lives on nodes."""

    def __init__(self, topology_path: str | Path | None = None) -> None:
        path = Path(topology_path) if topology_path else DEFAULT_TOPOLOGY_PATH
        with path.open(encoding="utf-8") as f:
            spec = yaml.safe_load(f)

        self._spec = spec
        self._mission_critical: set[str] = set(spec.get("mission", {}).get("critical_nodes", []))
        self.graph: nx.DiGraph = nx.DiGraph()

        for node in spec["nodes"]:
            node_id = node["id"]
            self.graph.add_node(
                node_id,
                type=node.get("type"),
                zone=node.get("zone"),
                criticality=int(node.get("criticality", 0)),
                services=list(node.get("services") or []),
                modeled_vulns=list(node.get("modeled_vulns") or []),
                loot=list(node.get("loot") or []),
                defender_monitor=bool(node.get("defender_monitor", False)),
                mission_critical=bool(node.get("mission_critical", False))
                or node_id in self._mission_critical,
                compromised=False,
                isolated=False,
                exfiltrated=False,
                privilege="none",  # none -> user -> root
            )

        for edge in spec["edges"]:
            self.graph.add_edge(
                edge["source"],
                edge["target"],
                trust=edge.get("trust", "medium"),
                requires_cred=edge.get("requires_cred"),
                active=True,
            )

        # Mission objective: the crown-jewel node(s) the attacker must exfiltrate.
        self.goal_nodes: set[str] = set(self._mission_critical)
        # The protected zone = where the crown jewels live. Crossing INTO it
        # requires root (access-level enforcement); same for exfiltration.
        self.protected_zone: str | None = next(
            (self.graph.nodes[n].get("zone") for n in self.goal_nodes), None
        )
        # Credentials the attacker has collected (unlock cred-gated edges).
        self.looted: set[str] = set()

    def node_exists(self, node: str) -> bool:
        return node in self.graph

    def node_zone(self, node: str) -> str | None:
        return self.graph.nodes[node].get("zone")

    def crossing_into_protected(self, src: str, tgt: str) -> bool:
        """True if moving src->tgt enters the protected (crown-jewel) zone from
        outside it — the boundary that requires elevated privilege to cross."""
        return (self.protected_zone is not None
                and self.node_zone(tgt) == self.protected_zone
                and self.node_zone(src) != self.protected_zone)

    def get_neighbors(self, node: str) -> list[str]:
        """Adjacent nodes reachable via active edges (both directions)."""
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")

        neighbors: set[str] = set()
        for _, target, data in self.graph.out_edges(node, data=True):
            if data.get("active", True):
                neighbors.add(target)
        for source, _, data in self.graph.in_edges(node, data=True):
            if data.get("active", True):
                neighbors.add(source)
        return sorted(neighbors)

    def get_vulns(self, node: str) -> list[dict[str, Any]]:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        return list(self.graph.nodes[node].get("modeled_vulns") or [])

    def set_compromised(self, node: str, compromised: bool = True) -> None:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        self.graph.nodes[node]["compromised"] = compromised

    def is_compromised(self, node: str) -> bool:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        return bool(self.graph.nodes[node]["compromised"])

    def set_isolated(self, node: str, isolated: bool = True) -> None:
        """Defender response: isolate node by deactivating all incident edges."""
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        self.graph.nodes[node]["isolated"] = isolated
        for u, v, data in list(self.graph.edges(data=True)):
            if u == node or v == node:
                data["active"] = not isolated

    def is_isolated(self, node: str) -> bool:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        return bool(self.graph.nodes[node]["isolated"])

    def has_route(self, source: str, target: str) -> bool:
        """Is there a DIRECTED attack path from source to target over active edges?

        Directed (uses edge orientation, unlike the bidirectional get_neighbors used
        for adjacency/viz) so that a node with only inbound edges is a genuine
        dead-end — the attacker can reach it but cannot advance from it.
        """
        if not self.node_exists(source) or not self.node_exists(target):
            raise KeyError(f"Unknown node: {source} or {target}")
        active = self.graph.edge_subgraph(
            [(u, v) for u, v, d in self.graph.edges(data=True) if d.get("active", True)]
        )
        return active.has_node(source) and active.has_node(target) \
            and nx.has_path(active, source, target)

    def set_exfiltrated(self, node: str, exfiltrated: bool = True) -> None:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        self.graph.nodes[node]["exfiltrated"] = exfiltrated

    # -- privilege ------------------------------------------------------------
    def set_privilege(self, node: str, level: str) -> None:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        self.graph.nodes[node]["privilege"] = level

    def get_privilege(self, node: str) -> str:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        return self.graph.nodes[node].get("privilege", "none")

    # -- loot / credentials ---------------------------------------------------
    def get_loot(self, node: str) -> list[dict[str, Any]]:
        if not self.node_exists(node):
            raise KeyError(f"Unknown node: {node}")
        return list(self.graph.nodes[node].get("loot") or [])

    def loot_node(self, node: str) -> list[str]:
        """Collect a compromised node's loot; returns the ids picked up."""
        picked = [item["id"] for item in self.get_loot(node)]
        self.looted.update(picked)
        return picked

    def has_cred(self, cred_id: str | None) -> bool:
        """True if no credential is required, or the attacker has looted it."""
        return cred_id is None or cred_id in self.looted

    # -- mission --------------------------------------------------------------
    def is_goal_reached(self) -> bool:
        """The mission objective is met once a goal node has been exfiltrated."""
        return any(
            self.graph.nodes[n].get("exfiltrated") for n in self.goal_nodes
        )

    def get_mission_integrity(self) -> float:
        """
        Percentage of mission-critical nodes that are uncompromised and not exfiltrated.
        Returns 100.0 when there are no critical nodes.
        """
        critical = [
            n
            for n, data in self.graph.nodes(data=True)
            if data.get("mission_critical") or n in self._mission_critical
        ]
        if not critical:
            return 100.0

        safe = 0
        for node in critical:
            data = self.graph.nodes[node]
            if not data.get("compromised") and not data.get("exfiltrated"):
                safe += 1
        return round(100.0 * safe / len(critical), 2)

    def to_dict(self) -> dict[str, Any]:
        """Snapshot for API / viz: nodes, edges, and mission integrity."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            nodes.append(
                {
                    "id": node_id,
                    "type": data.get("type"),
                    "zone": data.get("zone"),
                    "criticality": data.get("criticality", 0),
                    "services": data.get("services", []),
                    "modeled_vulns": data.get("modeled_vulns", []),
                    "loot": data.get("loot", []),
                    "defender_monitor": data.get("defender_monitor", False),
                    "mission_critical": data.get("mission_critical", False),
                    "compromised": data.get("compromised", False),
                    "isolated": data.get("isolated", False),
                    "exfiltrated": data.get("exfiltrated", False),
                    "privilege": data.get("privilege", "none"),
                }
            )
        edges = []
        for source, target, data in self.graph.edges(data=True):
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "trust": data.get("trust", "medium"),
                    "requires_cred": data.get("requires_cred"),
                    "active": data.get("active", True),
                }
            )
        return {
            "mission": self._spec.get("mission", {}),
            "mission_integrity": self.get_mission_integrity(),
            "goal_reached": self.is_goal_reached(),
            "looted": sorted(self.looted),
            "nodes": nodes,
            "edges": edges,
        }


def load_twin(topology_path: str | Path | None = None) -> NetworkTwin:
    return NetworkTwin(topology_path=topology_path)
