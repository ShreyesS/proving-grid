"""Digital twin: load topology.yaml into a networkx graph and track modeled state.

SIMULATION ONLY. Nothing here touches a real host. The graph holds the modeled
network; a mutable `state` layer on each node/edge records what the attacker and
defender have done to the twin.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import networkx as nx
import yaml

# topology.yaml lives at the repo root, one level above backend/.
TOPOLOGY_PATH = Path(__file__).resolve().parent.parent / "topology.yaml"


def _initial_node_state() -> dict[str, Any]:
    """Fresh modeled state for a node at the start of a run."""
    return {
        "compromised": False,   # attacker has an exploited foothold
        "reachable": False,     # discovered via scan / lateral_move
        "privilege": "none",    # none -> user -> root
        "isolated": False,      # defender has cut this node off
        "looted": [],           # ids of credentials/data collected here
    }


def _initial_edge_state() -> dict[str, Any]:
    return {
        "active": True,      # reroute_traffic can deactivate edges
        "traversed": False,  # attacker has moved across this edge
    }


class Twin:
    """The modeled network and its live state, backed by a networkx DiGraph."""

    def __init__(self, graph: nx.DiGraph, meta: dict[str, Any],
                 monitoring: dict[str, Any]):
        self.graph = graph
        self.meta = meta
        self.monitoring = monitoring
        self.goal_node: str = meta.get("goal_node")
        self.entrypoint: str = meta.get("entrypoint")

    # -- construction ----------------------------------------------------
    @classmethod
    def from_yaml(cls, path: Path | str = TOPOLOGY_PATH) -> "Twin":
        with open(path, "r") as f:
            spec = yaml.safe_load(f)

        g = nx.DiGraph()
        for node in spec.get("nodes", []):
            node = dict(node)
            node_id = node.pop("id")
            g.add_node(
                node_id,
                static=node,                 # immutable topology facts
                state=_initial_node_state(),
            )
        for edge in spec.get("edges", []):
            edge = dict(edge)
            src, tgt = edge.pop("source"), edge.pop("target")
            g.add_edge(src, tgt, static=edge, state=_initial_edge_state())

        twin = cls(g, spec.get("meta", {}), spec.get("monitoring", {}))
        # The attacker always starts with a foothold on the entrypoint.
        if twin.entrypoint and twin.entrypoint in g:
            s = g.nodes[twin.entrypoint]["state"]
            s["compromised"] = True
            s["reachable"] = True
            s["privilege"] = "root"
        return twin

    # -- queries ---------------------------------------------------------
    def node(self, node_id: str) -> dict[str, Any]:
        return self.graph.nodes[node_id]

    def neighbors_of(self, node_id: str) -> list[str]:
        """Outbound neighbors reachable over currently-active edges."""
        out = []
        for _, tgt, data in self.graph.out_edges(node_id, data=True):
            if data["state"]["active"]:
                out.append(tgt)
        return out

    def compromised_nodes(self) -> list[str]:
        return [n for n, d in self.graph.nodes(data=True)
                if d["state"]["compromised"]]

    def is_goal_reached(self) -> bool:
        """Goal is reached only when the goal node's loot has been exfiltrated."""
        if not self.goal_node:
            return False
        loot_ids = [l["id"] for l in
                    self.graph.nodes[self.goal_node]["static"].get("loot", [])]
        looted = self.graph.nodes[self.goal_node]["state"]["looted"]
        return any(lid in looted for lid in loot_ids)

    def path_exists(self, source: str, target: str) -> bool:
        """Is there a path over active, non-isolated edges/nodes?"""
        active = nx.DiGraph()
        for n, d in self.graph.nodes(data=True):
            if not d["state"]["isolated"]:
                active.add_node(n)
        for u, v, d in self.graph.edges(data=True):
            if d["state"]["active"] and u in active and v in active:
                active.add_edge(u, v)
        return active.has_node(source) and active.has_node(target) \
            and nx.has_path(active, source, target)

    # -- serialization (for HTTP / WebSocket) ----------------------------
    def to_dict(self) -> dict[str, Any]:
        """Full snapshot for the UI: nodes (static + state) and edges."""
        nodes = []
        for nid, d in self.graph.nodes(data=True):
            nodes.append({"id": nid, **d["static"], "state": d["state"]})
        edges = []
        for u, v, d in self.graph.edges(data=True):
            edges.append({"source": u, "target": v, **d["static"],
                          "state": d["state"]})
        return {
            "meta": self.meta,
            "monitoring": self.monitoring,
            "nodes": nodes,
            "edges": edges,
        }
