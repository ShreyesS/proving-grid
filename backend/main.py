"""FastAPI app: expose twin state for viz; stream a bounded attack run over WS.

GET  /state  -> current twin snapshot (fresh twin)
POST /run    -> run one bounded rehearsal; broadcast reasoning + state to /ws clients
WS   /ws     -> live event stream (state / reasoning / run_end)
"""

from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from attacker import run_attack
from llm import make_brain
from twin import load_twin

app = FastAPI(title="Proving Grid")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    """Tracks live WebSocket clients and broadcasts run events to all of them."""

    def __init__(self) -> None:
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.discard(ws)

    async def broadcast(self, message: dict) -> None:
        payload = json.dumps(message)
        for ws in list(self.active):
            try:
                await ws.send_text(payload)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()
# Only one rehearsal at a time — keeps the streamed state coherent for the demo.
_run_in_progress = False


@app.get("/state")
def get_state() -> dict:
    twin = load_twin()
    return twin.to_dict()


@app.post("/run")
async def run(brain: str = "auto"):
    """Trigger a bounded attack rehearsal; events stream to all /ws clients.

    brain: 'auto' (LLM if ANTHROPIC_API_KEY is set, else scripted) | 'llm' | 'scripted'.
    """
    global _run_in_progress
    if _run_in_progress:
        return JSONResponse(
            status_code=409, content={"error": "a run is already in progress"}
        )
    _run_in_progress = True
    try:
        twin = load_twin()
        decide = make_brain(brain)

        async def emit(message: dict) -> None:
            await manager.broadcast(message)

        outcome = await run_attack(twin, decide, emit)
        return {"outcome": outcome, "brain": brain}
    finally:
        _run_in_progress = False


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        # Send the current snapshot on connect so the UI paints immediately.
        await websocket.send_text(
            json.dumps({"type": "state", "payload": load_twin().to_dict()})
        )
        while True:
            # We don't expect client messages yet; this keeps the socket open
            # and lets us detect disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
