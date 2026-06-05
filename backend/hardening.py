"""Patch-and-prove: an in-process hardening overlay.

When a run finds an attack path, you can patch the specific CVEs the agent
exploited. We keep a set of patched vuln IDs and apply it on every twin load
(marking those vulns `patched: true`) — so re-running shows whether the patch
actually closed the path or the agent just found another way in.

Kept out of topology.yaml on purpose: the source file stays pristine and the
hardening is fully resettable (Restore). No database.
"""
from __future__ import annotations

from typing import Any

# Vuln IDs the operator has patched this session.
HARDENED_VULNS: set[str] = set()


def patch(vuln_ids: list[str]) -> None:
    HARDENED_VULNS.update(v for v in vuln_ids if v)


def reset() -> None:
    HARDENED_VULNS.clear()


def status() -> list[str]:
    return sorted(HARDENED_VULNS)


def apply(twin: Any) -> Any:
    """Remove every patched CVE from its node on a freshly-loaded twin — the vuln
    is gone (no longer in the node's list / tooltip, and no longer exploitable)."""
    if not HARDENED_VULNS:
        return twin
    for _, data in twin.graph.nodes(data=True):
        vulns = data.get("modeled_vulns")
        if vulns:
            data["modeled_vulns"] = [v for v in vulns
                                     if v.get("id") not in HARDENED_VULNS]
    return twin
