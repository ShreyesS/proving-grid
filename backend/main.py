"""FastAPI app: expose twin state for viz; stream a bounded attack run over WS.

GET  /state  -> current twin snapshot (fresh twin)
POST /run    -> run one bounded rehearsal; broadcast reasoning + state to /ws clients
WS   /ws     -> live event stream (state / reasoning / run_end)
"""

from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

import yaml as _yaml

from attacker import run_attack
from llm import make_brain
from memory import MEMORY
from twin import DEFAULT_TOPOLOGY_PATH, load_twin

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


@app.get("/topology", response_class=PlainTextResponse)
def get_topology() -> str:
    return DEFAULT_TOPOLOGY_PATH.read_text(encoding="utf-8")


@app.put("/topology", response_class=PlainTextResponse)
async def put_topology(request) -> str:
    text = (await request.body()).decode("utf-8")
    try:
        _yaml.safe_load(text)  # validate before writing
    except _yaml.YAMLError as e:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {e}")
    DEFAULT_TOPOLOGY_PATH.write_text(text, encoding="utf-8")
    return text


@app.get("/state")
def get_state() -> dict:
    twin = load_twin()
    return twin.to_dict()


@app.post("/run")
async def run(brain: str = "auto", defended: bool = False, use_memory: bool = True):
    """Trigger a bounded attack rehearsal; events stream to all /ws clients.

    brain: 'auto' (LLM if ANTHROPIC_API_KEY is set, else scripted) | 'llm' | 'scripted'.
    defended: if true, a defender detects + contains the attacker (the A/B duel).
    use_memory: feed prior discovered paths so the agent hunts a NEW route.
    """
    global _run_in_progress
    if _run_in_progress:
        return JSONResponse(
            status_code=409, content={"error": "a run is already in progress"}
        )
    _run_in_progress = True
    try:
        twin = load_twin()
        # Cross-run memory: feed prior paths so the agent hunts a new route.
        prior = MEMORY.path_summaries() if use_memory else None
        decide = make_brain(brain, prior_paths=prior)

        async def emit(message: dict) -> None:
            await manager.broadcast(message)

        outcome = await run_attack(twin, decide, emit, defended=defended,
                                   memory=MEMORY)
        return {"outcome": outcome, "brain": brain, "defended": defended,
                "memory_paths": MEMORY.stats()["distinct_paths"]}
    finally:
        _run_in_progress = False


@app.post("/eval")
async def run_eval(n: int = 5, defended: bool = True, brain: str = "auto"):
    """Run N rehearsals headless (memory on, so each hunts a new path), then
    report aggregate agent-performance stats. Streams eval_progress to /ws."""
    global _run_in_progress
    if _run_in_progress:
        return JSONResponse(status_code=409,
                            content={"error": "a run is already in progress"})
    n = max(1, min(n, 25))
    _run_in_progress = True

    async def emit(message: dict) -> None:  # only progress, not per-step noise
        await manager.broadcast(message)

    async def noop(_message: dict) -> None:
        return None

    try:
        await emit({"type": "eval_start", "payload": {"n": n}})
        for i in range(n):
            twin = load_twin()
            decide = make_brain(brain, prior_paths=MEMORY.path_summaries())
            outcome = await run_attack(twin, decide, noop, defended=defended,
                                       memory=MEMORY, step_delay=0)
            await emit({"type": "eval_progress",
                        "payload": {"run": i + 1, "of": n, "outcome": outcome,
                                    "stats": MEMORY.stats()}})
        stats = MEMORY.stats()
        await emit({"type": "eval_done", "payload": stats})
        return stats
    finally:
        _run_in_progress = False


@app.get("/memory")
def get_memory() -> dict:
    return MEMORY.stats()


@app.post("/memory/clear")
def clear_memory() -> dict:
    MEMORY.clear()
    return {"cleared": True}


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
