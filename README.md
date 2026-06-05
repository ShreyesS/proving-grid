# proving-grid

Cyber-range **digital twin** (hackathon): a *simulated* CDN + corporate network where an autonomous **LLM attacker** reasons about the topology and chains an attack path toward the customer database — while you watch it think, live. Everything acts on **modeled state only** — never a real host, port, or exploit. See [CLAUDE.md](./CLAUDE.md) for the full spec.

> **Value:** the attacker discovers *attack paths you didn't know you had*. Run it against a twin of your network, see how an AI would chain your exposures to the crown jewel, then go fix the real thing.

## What's in the repo

| Piece | Role |
|-------|------|
| [`topology.yaml`](./topology.yaml) | Single source of truth — nodes, zones, edges, modeled vulns, credentials, mission |
| [`backend/twin.py`](./backend/twin.py) | Loads YAML into a **networkx** graph; compromise / loot / privilege / isolation state, mission integrity |
| [`backend/tools.py`](./backend/tools.py) | The modeled attacker tools (`scan`, `exploit`, `lateral_move`, `escalate`, `loot`, `exfiltrate`) — act on twin state only |
| [`backend/attacker.py`](./backend/attacker.py) | The bounded **perceive → reason → act → observe** loop; streams reasoning + state; emits an attack-path findings artifact |
| [`backend/llm.py`](./backend/llm.py) | Swappable LLM interface — the Anthropic tool-use brain (streams reasoning token-by-token); falls back to a scripted brain with no key |
| [`backend/main.py`](./backend/main.py) | **FastAPI** — `GET /state`, `POST /run`, `GET`/`PUT /topology`, WebSocket `/ws` (broadcasts the live run) |
| [`frontend/`](./frontend/) | **React + Vite + Cytoscape** — live topology, scoreboard, streaming reasoning panel, and Run / Reset / Patch controls |

**Data flow:** `topology.yaml` → `twin.py` → attacker loop (LLM picks the next tool) → tools mutate modeled state → every change streams over WebSocket → React UI. Vite proxies `/state`, `/run`, `/topology`, and `/ws` to port 8000 in dev.

## Prerequisites

- **Python 3.11+** (with `venv`)
- **Node.js 18+** and **npm**
- An **Anthropic API key** — optional, but required to run the *real* LLM attacker (without it, the app falls back to a deterministic scripted attacker so the demo still works)

> Not containerized — there is no Docker. You run it directly with Python + Node as below.

## Quick start

```bash
# from the repo root, after clone — first run installs everything
./scripts/dev.sh
```

This creates `backend/.venv` + installs Python deps, runs `npm install` in `frontend/` and at the root (for `concurrently`), then starts **both** the API (`:8000`) and the UI (`:5173`).

Open **http://localhost:5173**. Press **Ctrl+C** to stop.

`npm run dev` from the root does the same once setup has run once.

## Enable the LLM attacker (API key)

The attacker's brain is a real Anthropic model. Give it a key via a **git-ignored** `.env` file:

```bash
# backend/.env  —  exactly one line, no quotes, no "export"
ANTHROPIC_API_KEY=sk-ant-...your-full-key...
```

- The key must be the **full** value (~100+ chars) on a single `ANTHROPIC_API_KEY=...` line. (A bare key with no `ANTHROPIC_API_KEY=` prefix is the #1 gotcha.)
- `backend/.env` is in `.gitignore` — it is never committed.
- The backend loads it automatically (`llm.py`), so `npm run dev` and a manual `uvicorn` both pick it up.
- **No key?** That's fine — runs fall back to the scripted attacker (`brain=auto`). Good for offline / stage-backup.

Optional env vars (in the same `.env` or your shell):

| Var | Default | Purpose |
|-----|---------|---------|
| `PROVING_GRID_MODEL` | `claude-sonnet-4-6` | Which Claude model the attacker uses |
| `PROVING_GRID_LLM_TEMPERATURE` | `0.6` | Higher = more path variety across runs |
| `PROVING_GRID_LLM_TIMEOUT` | `30` | Per-call timeout (seconds) |

## Run an attack

With the UI open at `:5173`, click **Run Attack** in the header. The model's thinking streams into the **Attacker Reasoning** panel token-by-token, each step tagged with its MITRE technique and the exact CVE / credential / trust edge it's exploiting, ending with a green **ATTACK PATH DISCOVERED** banner. The graph lights up red along the path; the scoreboard drops as nodes fall. Run it again — it often picks a **different** route.

You can also trigger a run from the API directly (handy for the `brain` switch):

```bash
curl -X POST "localhost:8000/run?brain=llm"
```

| Request | Brain | Notes |
|---------|-------|-------|
| `POST /run?brain=llm` | Real Anthropic model | The live demo |
| `POST /run?brain=scripted` | Deterministic best path | **No API call** — safe stage fallback |
| `POST /run` | `auto` | LLM if a key is set, else scripted (the Run Attack button uses this) |

A run always terminates (goal reached, blocked, or step/timeout cap). A failed LLM or tool call degrades into a reasoning line — it never crashes the run or the socket.

### UI controls

| Button | What it does |
|--------|-------------|
| **Run Attack** | `POST /run` — starts a bounded rehearsal, streams state + reasoning over WebSocket |
| **Reset** | Reloads `GET /state` — repaints the topology clean without running an attack |
| **Patch Network** | Opens the `topology.yaml` editor — edit vulns or add controls; *Save & Apply* writes to disk (`PUT /topology`) and repaints immediately, so you can re-run and see how the patch holds up |

## Manual setup and run

If you prefer explicit steps instead of `./scripts/dev.sh`:

```bash
# First time only
npm install                 # root — installs concurrently
npm run setup:backend       # backend/.venv + pip install -r requirements.txt
npm run setup:frontend      # frontend deps
# (or all of the above: npm run setup)

# Every dev session
npm run dev                 # API :8000 + UI :5173 in parallel
```

> **Upgrading an existing checkout?** The backend gained `anthropic` + `python-dotenv`. Re-run `npm run setup:backend` (or `cd backend && .venv/bin/pip install -r requirements.txt`).

### npm scripts reference

| Script | What it does |
|--------|----------------|
| `npm run setup` | `setup:backend` + `setup:frontend` |
| `npm run setup:backend` | `python3 -m venv backend/.venv` + install `requirements.txt` |
| `npm run setup:frontend` | `npm install` inside `frontend/` |
| `npm run dev` | API on `:8000` and UI on `:5173` (via `concurrently`) |
| `npm run dev:api` | Backend only |
| `npm run dev:ui` | Frontend only |

### Backend / frontend separately (optional)

```bash
# API only (:8000)
cd backend && .venv/bin/uvicorn main:app --reload --port 8000
#   sanity check: http://localhost:8000/state returns the twin snapshot JSON

# UI only (:5173) — backend must already be running
cd frontend && npm run dev
```

## Visualization

- **Nodes:** blue = normal, red = compromised, gray = isolated, orange = exfiltrated
- **Edges:** gray by default; trust shown as solid / dashed / dotted; **red** = outbound path from a compromised host
- **Scoreboard:** mission integrity %, compromised / isolated counts
- **Attacker reasoning:** streams the agent's thinking live — MITRE technique tag, `exploiting: <CVE/cred/edge>` highlight per step, then the discovered attack path

Hover nodes for services and modeled vulns; hover edges for trust and path status.

## Tests

```bash
cd backend && .venv/bin/python -m pytest        # network-free; no API key needed
```

The LLM brain is tested with an injected fake client, so the suite runs offline.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Empty graph or red "Cannot reach the API" | Start the backend (`npm run dev` / `npm run dev:api`) before or with the UI |
| Reasoning panel empty but graph moved | The WS connected after the run started — run it again with the page open |
| **Run Attack** does nothing | The `/run` proxy must be in `vite.config.js`; restart the UI after pulling |
| `POST /run?brain=llm` returns an auth/connection error | Check `backend/.env` is exactly `ANTHROPIC_API_KEY=sk-ant-...` (full key, one line, no quotes) |
| Run falls back to scripted unexpectedly | No / empty key in `backend/.env`; `brain=auto` uses the LLM only when a key is present |
| `uvicorn: command not found` | Run `npm run setup:backend` |
| Port 8000 or 5173 in use | Stop the other process or change ports in `vite.config.js` / uvicorn args |
| `./scripts/dev.sh: Permission denied` | `chmod +x scripts/dev.sh` |

## Project layout

```
proving-grid/
├── topology.yaml          # network definition (single source of truth)
├── package.json           # root dev scripts (concurrently)
├── scripts/dev.sh         # one-shot setup + dev
├── backend/
│   ├── main.py            # FastAPI: /state, /run, /topology, /ws
│   ├── twin.py            # graph + modeled state + queries
│   ├── tools.py           # modeled attacker tools
│   ├── attacker.py        # bounded perceive→reason→act→observe loop + findings
│   ├── llm.py             # swappable LLM brain (Anthropic tool-use, streaming)
│   ├── .env               # ANTHROPIC_API_KEY (git-ignored, you create it)
│   ├── requirements.txt
│   └── tests/
└── frontend/
    ├── src/
    │   ├── App.jsx
    │   ├── Topology.jsx
    │   ├── Scoreboard.jsx
    │   └── ReasoningPanel.jsx   # live streaming reasoning
    └── vite.config.js     # proxies /state, /run, /topology, /ws → :8000
```

> **Simulation only.** No real network scanning, packets, or exploits. The attacker's tools read and mutate the modeled `networkx` graph; the only outbound call is to the LLM API in `llm.py`.
