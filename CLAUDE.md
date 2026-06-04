# Proving Grid — build context

## What we're building
A cyber-range / digital-twin demo (hackathon, judged Fri). A high-fidelity SIMULATION of a
network (CDN edge + corporate segment) where an autonomous LLM-driven ATTACKER agent reasons
about the topology and chains an attack path toward a goal (exfiltrate the customer DB), while
a DEFENDER detects the intrusion and responds — isolating compromised nodes and rerouting
traffic so the mission survives. A live web UI shows the topology, the attacker's reasoning
stream, and a scoreboard (time-to-compromise / detect / contain, mission-integrity %).
Vision: defenders rehearse against AI-driven attacks in a digital twin so they win in prod.

## Hard constraints (do not violate)
- SIMULATION ONLY. Attacker tools act on the twin's MODELED STATE — never real exploits or
  payloads. `exploit(node)` checks modeled vulns and updates compromise state. Nothing in this
  repo touches a real host, port, or network.
- `topology.yaml` is the single source of truth, driving BOTH twin and viz: nodes
  (id, type, services, modeled_vulns), trust/network edges, defender monitoring points.
- Attacker = LLM via API behind a SWAPPABLE interface (see llm.py). The model is
  interchangeable; the moat is the twin + resilience engine + the data each run produces.
  This is NOT a wrapper — engineering substance lives in the twin, orchestration, and
  defender, not the prompt.
- Attacker loop: perceive -> reason -> act -> observe, looping until goal/blocked/contained.

## Architecture / data flow
topology.yaml  ->  twin (networkx state graph)  ->  attacker loop (LLM picks next tool)
  ->  tools mutate modeled compromise state  ->  defender observes + responds (isolate/reroute)
  ->  every state change streams over WebSocket to the React UI (topology + reasoning + score)

## Repo layout (target — build toward this)
proving-grid/
├── CLAUDE.md
├── topology.yaml            # single source of truth
├── backend/
│   ├── main.py              # FastAPI app + WebSocket endpoints; orchestrates a run
│   ├── twin.py              # load topology.yaml into networkx; modeled state + queries
│   ├── attacker.py          # perceive->reason->act->observe loop; bounded
│   ├── tools.py             # scan / exploit / lateral_move / escalate / exfiltrate (modeled)
│   ├── defender.py          # detection rules + isolate_node / reroute_traffic
│   ├── llm.py               # swappable LLM interface (one function, model behind it)
│   ├── requirements.txt
│   └── tests/
└── frontend/
    ├── src/
    │   ├── App.jsx
    │   ├── Topology.jsx     # cytoscape.js topology + live node state
    │   ├── ReasoningPanel.jsx
    │   └── Scoreboard.jsx
    └── package.json

## Commands
# backend
cd backend && pip install -r requirements.txt        # install
cd backend && uvicorn main:app --reload --port 8000  # run API + WebSocket
cd backend && pytest                                 # run tests
# frontend
cd frontend && npm install                           # install
cd frontend && npm run dev                           # run UI (Vite, default :5173)
# a rehearsal is triggered from the UI (or POST /run); attacker is bounded by max_steps + timeout

## Conventions
- Use MITRE ATT&CK vocabulary in labels/comments: recon, initial access, privilege escalation,
  lateral movement, exfiltration.
- All state is in-memory in the networkx graph. No database.
- Stack: Python, networkx, FastAPI + WebSocket; React + cytoscape.js.
- Detection rule-based first (reliable); AI defender is a stretch goal, behind the same interface.
- Keep the LLM call isolated in llm.py so the model is swappable in one place.

## Do NOT
- Do NOT add real network-scanning, packet, or exploit libraries (nmap, scapy, metasploit, etc.).
- Do NOT introduce a database, ORM, or persistence layer — state lives in the graph.
- Do NOT make outbound network calls except the LLM API in llm.py.
- Do NOT let the attacker run unbounded — always enforce max_steps and a timeout.

## Demo invariants (live demo > fidelity)
- Build VERTICALLY: a thin slice through twin -> attacker -> defender -> viz before widening.
- The attacker ALWAYS terminates (goal reached, blocked, contained, or step/timeout cap).
- A failed LLM call or tool error must NOT crash the run or the UI — degrade gracefully.
- Keep a recorded backup run in case the live LLM call fails on stage.
