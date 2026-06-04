# proving-grid

Cyber-range digital twin (hackathon): a **simulated** CDN + corporate network where an attacker and defender operate on modeled state (never real hosts). See [CLAUDE.md](./CLAUDE.md) for the full spec.

## What’s in the repo

| Piece | Role |
|-------|------|
| [`topology.yaml`](./topology.yaml) | Single source of truth — nodes, edges, modeled vulns, mission |
| [`backend/twin.py`](./backend/twin.py) | Loads YAML into a **networkx** graph; compromise, isolation, mission integrity |
| [`backend/main.py`](./backend/main.py) | **FastAPI** — `GET /state`, WebSocket `/ws` (stub streams snapshot) |
| [`frontend/`](./frontend/) | **React + Vite + Cytoscape** — live topology, scoreboard, reasoning panel (stub) |

**Data flow:** `topology.yaml` → `twin.py` → API → UI (Vite proxies `/state` and `/ws` to port 8000 in dev).

## Prerequisites

- **Python 3.11+** (with `venv`)
- **Node.js 18+** and **npm**

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
- **Reasoning panel:** stub (“Waiting for attacker…”) until the attacker loop streams steps over WebSocket  

Hover nodes for services and modeled vulns; hover edges for trust and path status.

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
├── topology.yaml          # network definition
├── package.json           # root dev scripts (concurrently)
├── scripts/dev.sh         # one-shot setup + dev
├── backend/
│   ├── main.py            # FastAPI
│   ├── twin.py            # graph + queries
│   ├── requirements.txt
│   └── tests/
└── frontend/
    ├── src/
    │   ├── App.jsx
    │   ├── Topology.jsx
    │   ├── Scoreboard.jsx
    │   └── ReasoningPanel.jsx
    └── vite.config.js     # proxies /state, /ws → :8000
```
