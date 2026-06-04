"""FastAPI app: expose twin state for viz; WebSocket stub for future run streaming."""

from __future__ import annotations

import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from twin import load_twin

app = FastAPI(title="Proving Grid")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/state")
def get_state() -> dict:
    twin = load_twin()
    return twin.to_dict()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        twin = load_twin()
        await websocket.send_text(
            json.dumps({"type": "state", "payload": twin.to_dict()})
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
