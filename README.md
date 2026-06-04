# Proving Grid — build context

## What we're building
A cyber-range / digital-twin demo (hackathon, judged Fri). A high-fidelity SIMULATION
of a network (CDN edge + corporate segment) where an autonomous LLM-driven ATTACKER
agent reasons about the topology and chains an attack path toward a goal (exfiltrate the
customer DB), while a DEFENDER detects the intrusion and responds by isolating compromised
nodes and rerouting traffic so the mission survives. A live web UI shows the topology, the
attacker's reasoning stream, and a scoreboard (time-to-compromise / detect / contain,
mission-integrity %).

Vision: defenders rehearse against AI-driven attacks in a digital twin so they win in prod.

## Hard constraints (do not violate)
- SIMULATION ONLY. Attacker tools act on the twin's MODELED STATE — never real exploits or
  payloads. `exploit(node)` checks modeled vulns and updates compromise state.
- `topology.yaml` is the single source of truth, driving BOTH twin and viz: nodes
  (id, type, services, modeled_vulns), trust/network edges, defender monitoring points.
- Attacker = LLM via API behind a SWAPPABLE interface. The model is interchangeable; the
  moat is the twin + resilience engine + the data each run produces. This is NOT a wrapper —
  engineering substance lives in the twin, orchestration, and defender, not the prompt.
- Attacker loop: perceive -> reason -> act -> observe, looping until goal/blocked/contained.

## Stack
- Python; networkx for the network state graph
- FastAPI + WebSocket for state/actions + live streaming to the UI
- React + cytoscape.js (or vis-network) for topology; panels for reasoning + scoreboard
- Detection: rule-based first (reliable); AI defender as a stretch
- Attacker tools: scan, exploit, lateral_move, escalate, exfiltrate (all act on modeled state)

## Build sequence (each milestone independently demoable; commit after each)
1. topology.yaml schema + networkx load + render static topology in UI
2. Stubbed one-step attacker proving the full perceive->act->observe loop end to end
3. Real LLM attacker: reasons + chains a path; nodes update state live in UI
4. Defender: detect lateral movement -> isolate node -> reroute traffic (the "heal")
5. Reasoning-stream panel + scoreboard (compromise/detect/contain times, integrity %)
6. Polish, demo script, record a backup run

## Priorities
- Build VERTICALLY first: thin slice through twin -> attacker -> defender -> viz by midday.
- Reliability for a LIVE demo > simulation fidelity. Bound the attacker (max steps, timeout).
- Use MITRE ATT&CK vocabulary in labels/comments (recon, initial access, priv-esc, lateral
  movement, exfiltration).
