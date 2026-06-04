"""FastAPI app + WebSocket endpoint. Orchestrates a rehearsal run.

M0: serves the topology snapshot for the UI to render. POST /run and the WS
event stream are wired in later milestones.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from twin import Twin

app = FastAPI(title="Proving Grid", version="0.1.0")

# Vite dev server runs on :5173; allow it (and localhost variants) to call us.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/topology")
def get_topology() -> dict:
    """Full graph snapshot (nodes + edges + zones) for the initial UI render."""
    twin = Twin.from_yaml()
    return twin.to_dict()
