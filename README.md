# proving-grid

Cyber-range digital twin (hackathon). See [CLAUDE.md](./CLAUDE.md) for full spec.

## Run the UI locally

You need **two terminals** — backend first, then frontend.

**Terminal 1 — API (port 8000)**

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Terminal 2 — UI (port 5173)**

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** in your browser (not the backend URL).

The Vite dev server proxies `/state` and `/ws` to the backend. If the graph is empty or you see a red error, the backend is not running.

## Tests

```bash
cd backend && source .venv/bin/activate && pytest
```
