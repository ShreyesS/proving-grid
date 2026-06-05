# proving-grid

Cyber-range digital twin (hackathon): a **simulated** CDN + corporate network where an attacker and defender operate on modeled state (never real hosts). See [CLAUDE.md](./CLAUDE.md) for the full spec.

## What’s in the repo

| Piece | Role |
|-------|------|
| [`topology.yaml`](./topology.yaml) | Single source of truth — nodes, edges, modeled vulns, loot, mission |
| [`backend/twin.py`](./backend/twin.py) | Loads YAML into a **networkx** graph; compromise, isolation, privilege, loot, mission integrity |
| [`backend/tools.py`](./backend/tools.py) | Attacker tools: `scan`, `exploit`, `lateral_move`, `escalate`, `loot`, `exfiltrate` (simulation only) |
| [`backend/attacker.py`](./backend/attacker.py) | Perceive → decide → act → observe loop; bounded by `max_steps`; streams findings |
| [`backend/llm.py`](./backend/llm.py) | Swappable LLM brain (Anthropic tool-use); falls back to scripted brain if no API key |
| [`backend/main.py`](./backend/main.py) | **FastAPI** — `GET /state`, `POST /run`, `GET /PUT /topology`, WebSocket `/ws` |
| [`frontend/`](./frontend/) | **React + Vite + Cytoscape** — live topology, scoreboard, LLM reasoning panel |

**Data flow:** `topology.yaml` → `twin.py` → `POST /run` → attacker loop → WebSocket `/ws` → UI (Vite proxies `/state`, `/run`, `/topology`, `/ws` to port 8000 in dev).

## Prerequisites

- **Python 3.11+** (with `venv`)
- **Node.js 18+** and **npm**
- **Anthropic API key** — add to `backend/.env` as `ANTHROPIC_API_KEY=sk-ant-...`. Without it the run falls back to the deterministic scripted brain.

## Quick start (one command)

From the repo root, after clone:

```bash
./scripts/dev.sh
```

The script will, on first run:

1. Create `backend/.venv` and `pip install -r backend/requirements.txt`
2. Run `npm install` in `frontend/`
3. Run `npm install` at the repo root (for `concurrently`)
4. Start **both** the API and the UI

Then open **http://localhost:5173** in your browser.

Press **Ctrl+C** to stop both processes.

## Manual setup and run

If you prefer explicit steps instead of `./scripts/dev.sh`:

### First time only

```bash
# Repo root — installs concurrently (runs API + UI together)
npm install

# Backend venv + Python deps (networkx, PyYAML, FastAPI, …)
npm run setup:backend

# Frontend deps (React, Vite, Cytoscape, …)
npm run setup:frontend
```

Or run everything above in one go:

```bash
npm run setup
```

### Every dev session

```bash
npm run dev
```

This runs two processes in parallel:

| Label | Service | URL |
|-------|---------|-----|
| `api` | FastAPI + twin | http://localhost:8000 |
| `ui` | Vite + React viz | http://localhost:5173 |

Use **http://localhost:5173** for the graph. Do not open the API URL in the browser for the demo UI — the frontend proxies API traffic.

### npm scripts reference

| Script | What it does |
|--------|----------------|
| `npm run setup` | `setup:backend` + `setup:frontend` |
| `npm run setup:backend` | `python3 -m venv backend/.venv` + install `requirements.txt` |
| `npm run setup:frontend` | `npm install` inside `frontend/` |
| `npm run dev` | API on `:8000` and UI on `:5173` (via `concurrently`) |
| `npm run dev:api` | Backend only |
| `npm run dev:ui` | Frontend only |

## Run backend and frontend separately (optional)

**API only (port 8000)**

```bash
cd backend
source .venv/bin/activate   # Windows: .venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

Sanity check: http://localhost:8000/state should return JSON for the twin snapshot.

**UI only (port 5173)** — backend must already be running:

```bash
cd frontend
npm run dev
```

## Visualization

- **Nodes:** blue = normal, red = compromised, gray = isolated, orange = exfiltrated  
- **Edges:** gray by default; trust = solid / dashed / dotted; **red** = outbound path from a compromised host  
- **Scoreboard:** mission integrity %, compromised / isolated counts  
- **Reasoning panel:** streams the LLM attacker's live thinking step-by-step during a run  

Hover nodes for services and modeled vulns; hover edges for trust and path status.

### UI controls

| Button | What it does |
|--------|-------------|
| **Run Attack** | Triggers `POST /run` — starts a bounded rehearsal, streams state + reasoning over WebSocket |
| **Reset** | Reloads `GET /state` — repaints the topology clean without running an attack |
| **Patch Network** | Opens the `topology.yaml` editor — edit vulns or add controls, Save & Apply writes to disk and repaints immediately; run again to see how the patch holds up |

## Tests

```bash
cd backend
source .venv/bin/activate
pytest
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Empty graph or red “Cannot reach the API” | Start the backend (`npm run dev` or `npm run dev:api`) before or with the UI |
| `uvicorn: command not found` | Run `npm run setup:backend` or activate `backend/.venv` |
| Port 8000 or 5173 in use | Stop the other process or change ports in `vite.config.js` / uvicorn args |
| `./scripts/dev.sh: Permission denied` | `chmod +x scripts/dev.sh` |

## Project layout

```
proving-grid/
├── topology.yaml          # network definition (single source of truth)
├── package.json           # root dev scripts (concurrently)
├── scripts/dev.sh         # one-shot setup + dev
├── backend/
│   ├── main.py            # FastAPI — /state, /run, /topology, /ws
│   ├── twin.py            # graph + queries
│   ├── tools.py           # attacker tools (simulation only)
│   ├── attacker.py        # perceive → decide → act → observe loop
│   ├── llm.py             # swappable LLM brain (Anthropic tool-use)
│   ├── .env               # ANTHROPIC_API_KEY (git-ignored)
│   ├── requirements.txt
│   └── tests/
└── frontend/
    ├── src/
    │   ├── App.jsx
    │   ├── Topology.jsx
    │   ├── Scoreboard.jsx
    │   └── ReasoningPanel.jsx
    └── vite.config.js     # proxies /state, /run, /topology, /ws → :8000
```
