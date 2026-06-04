#!/usr/bin/env bash
# One command: install deps if needed, then run API + UI together.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x backend/.venv/bin/uvicorn ]]; then
  echo "→ First-time backend setup…"
  npm run setup:backend
fi

if [[ ! -d frontend/node_modules ]]; then
  echo "→ First-time frontend setup…"
  npm run setup:frontend
fi

if [[ ! -d node_modules ]]; then
  echo "→ Installing dev runner (concurrently)…"
  npm install
fi

echo "→ Starting API on :8000 and UI on :5173 — open http://localhost:5173"
exec npm run dev
