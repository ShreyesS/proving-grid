import { useCallback, useEffect, useState } from "react";
import Topology from "./Topology.jsx";
import Scoreboard from "./Scoreboard.jsx";
import ReasoningPanel from "./ReasoningPanel.jsx";

function wsUrl() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/ws`;
}

export default function App() {
  const [snapshot, setSnapshot] = useState(null);
  const [reasoningSteps, setReasoningSteps] = useState([]);
  const [wsStatus, setWsStatus] = useState("connecting");
  const [loadError, setLoadError] = useState(null);

  const applyMessage = useCallback((msg) => {
    if (msg.type === "state" && msg.payload) {
      setSnapshot(msg.payload);
    }
    if (msg.type === "reasoning" && msg.payload) {
      setReasoningSteps((prev) => [...prev, msg.payload]);
    }
  }, []);

  useEffect(() => {
    fetch("/state")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data) => {
        setSnapshot(data);
        setLoadError(null);
      })
      .catch((err) => {
        console.error("Failed to load /state:", err);
        setLoadError(
          "Cannot reach the API. Start the backend first (see README), then refresh."
        );
      });
  }, []);

  useEffect(() => {
    const ws = new WebSocket(wsUrl());

    ws.onopen = () => setWsStatus("connected");
    ws.onclose = () => setWsStatus("disconnected");
    ws.onerror = () => setWsStatus("error");

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        applyMessage(msg);
      } catch (err) {
        console.error("WebSocket message parse error:", err);
      }
    };

    return () => ws.close();
  }, [applyMessage]);

  return (
    <div className="app">
      <header className="app-header">
        <h1>Proving Grid — Network Twin</h1>
        <span style={{ fontSize: "0.75rem", color: "#8b9cb3" }}>
          WebSocket: {wsStatus}
        </span>
      </header>
      <main className="app-main">
        {loadError ? (
          <div
            style={{
              padding: 24,
              color: "#fca5a5",
              fontFamily: "monospace",
              fontSize: "0.9rem",
              lineHeight: 1.6,
            }}
          >
            <p>{loadError}</p>
            <pre style={{ color: "#94a3b8", marginTop: 16 }}>
              {`cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# other terminal:
cd frontend && npm install && npm run dev

# open http://localhost:5173`}
            </pre>
          </div>
        ) : !snapshot ? (
          <p style={{ padding: 24, color: "#8b9cb3" }}>Loading topology…</p>
        ) : (
          <Topology snapshot={snapshot} />
        )}
      </main>
      <aside className="app-sidebar">
        <Scoreboard snapshot={snapshot} />
        <ReasoningPanel steps={reasoningSteps} />
      </aside>
    </div>
  );
}
