import { useCallback, useEffect, useState } from "react";
import Topology from "./Topology.jsx";
import Scoreboard from "./Scoreboard.jsx";
import ReasoningPanel from "./ReasoningPanel.jsx";

function wsUrl() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/ws`;
}

// Merge a streamed reasoning token into the in-progress step (by step number).
function upsertDelta(prev, step, chunk) {
  const i = prev.findIndex((s) => s.step === step && s.kind === "step");
  if (i === -1) {
    return [...prev, { step, kind: "step", thought: chunk, streaming: true }];
  }
  const next = prev.slice();
  next[i] = { ...next[i], thought: (next[i].thought || "") + chunk, streaming: true };
  return next;
}

// Finalize a step (after its tool ran) with technique / exposure / result.
function upsertFinal(prev, p) {
  if (p.kind === "finding" || p.kind === "error") {
    return [...prev, { ...p, streaming: false }];
  }
  const i = prev.findIndex((s) => s.step === p.step && s.kind === "step");
  const entry = {
    step: p.step,
    kind: "step",
    thought: p.thought || (i >= 0 ? prev[i].thought : ""),
    tool: p.tool,
    target: p.target,
    technique: p.technique,
    exposure: p.exposure,
    observation: p.observation,
    ok: p.ok,
    streaming: false,
  };
  if (i === -1) return [...prev, entry];
  const next = prev.slice();
  next[i] = entry;
  return next;
}

export default function App() {
  const [snapshot, setSnapshot] = useState(null);
  const [reasoningSteps, setReasoningSteps] = useState([]);
  const [wsStatus, setWsStatus] = useState("connecting");
  const [loadError, setLoadError] = useState(null);
  const [running, setRunning] = useState(false);
  const [showEditor, setShowEditor] = useState(false);
  const [yamlText, setYamlText] = useState("");
  const [saveStatus, setSaveStatus] = useState(null); // null | "saving" | "saved" | "error"

  function triggerRun() {
    fetch("/run", { method: "POST" }).catch((err) =>
      console.error("Failed to start run:", err)
    );
  }

  function reloadTopology() {
    fetch("/state")
      .then((r) => r.json())
      .then((data) => {
        setSnapshot(data);
        setReasoningSteps([]);
      })
      .catch((err) => console.error("Failed to reload topology:", err));
  }

  function openEditor() {
    fetch("/topology")
      .then((r) => r.text())
      .then((text) => {
        setYamlText(text);
        setSaveStatus(null);
        setShowEditor(true);
      })
      .catch((err) => console.error("Failed to load topology:", err));
  }

  function saveTopology() {
    setSaveStatus("saving");
    fetch("/topology", { method: "PUT", body: yamlText })
      .then((r) => {
        if (!r.ok) return r.text().then((t) => { throw new Error(t); });
        setSaveStatus("saved");
        setShowEditor(false);
        reloadTopology();
      })
      .catch((err) => {
        console.error("Failed to save topology:", err);
        setSaveStatus("error");
      });
  }

  const applyMessage = useCallback((msg) => {
    if (msg.type === "run_start") {
      setRunning(true);
      setReasoningSteps([]);
    }
    if (msg.type === "run_end") {
      setRunning(false);
    }
    if (msg.type === "state" && msg.payload) {
      setSnapshot(msg.payload);
    }
    if (msg.type === "reasoning_delta" && msg.payload) {
      const { step, chunk } = msg.payload;
      setReasoningSteps((prev) => upsertDelta(prev, step, chunk));
    }
    if (msg.type === "reasoning" && msg.payload) {
      setReasoningSteps((prev) => upsertFinal(prev, msg.payload));
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
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button
            onClick={triggerRun}
            disabled={running || wsStatus !== "connected"}
            style={{
              padding: "6px 16px",
              background: running ? "#374151" : "#dc2626",
              color: running ? "#9ca3af" : "#fff",
              border: "none",
              borderRadius: 6,
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: running ? "not-allowed" : "pointer",
              letterSpacing: "0.03em",
            }}
          >
            {running ? "Running…" : "Run Attack"}
          </button>
          <button
            onClick={reloadTopology}
            disabled={running}
            style={{
              padding: "6px 16px",
              background: "transparent",
              color: running ? "#4b5563" : "#8b9cb3",
              border: "1px solid",
              borderColor: running ? "#4b5563" : "#8b9cb3",
              borderRadius: 6,
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: running ? "not-allowed" : "pointer",
              letterSpacing: "0.03em",
            }}
          >
            Reset
          </button>
          <button
            onClick={openEditor}
            disabled={running}
            style={{
              padding: "6px 16px",
              background: "transparent",
              color: running ? "#4b5563" : "#8b9cb3",
              border: "1px solid",
              borderColor: running ? "#4b5563" : "#8b9cb3",
              borderRadius: 6,
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: running ? "not-allowed" : "pointer",
              letterSpacing: "0.03em",
            }}
          >
            Patch Network
          </button>
          <span style={{ fontSize: "0.75rem", color: "#8b9cb3" }}>
            WebSocket: {wsStatus}
          </span>
        </div>
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

      {showEditor && (
        <div style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: 100,
        }}>
          <div style={{
            background: "#1a2332", border: "1px solid #2a3544", borderRadius: 8,
            width: "min(860px, 90vw)", height: "80vh",
            display: "flex", flexDirection: "column", padding: 16, gap: 10,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>Patch Corporate Network — topology.yaml</span>
              <button onClick={() => setShowEditor(false)}
                style={{ background: "none", border: "none", color: "#8b9cb3", fontSize: "1.2rem", cursor: "pointer" }}>✕</button>
            </div>
            <textarea
              value={yamlText}
              onChange={(e) => { setYamlText(e.target.value); setSaveStatus(null); }}
              spellCheck={false}
              style={{
                flex: 1, background: "#0f1419", color: "#e7ecf3", border: "1px solid #2a3544",
                borderRadius: 6, padding: 12, fontFamily: "monospace", fontSize: "0.8rem",
                lineHeight: 1.6, resize: "none", outline: "none",
              }}
            />
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <button onClick={saveTopology} disabled={saveStatus === "saving"}
                style={{
                  padding: "6px 20px", background: saveStatus === "saving" ? "#374151" : "#2563eb",
                  color: "#fff", border: "none", borderRadius: 6, fontWeight: 600,
                  fontSize: "0.85rem", cursor: saveStatus === "saving" ? "not-allowed" : "pointer",
                }}>
                {saveStatus === "saving" ? "Saving…" : "Save & Apply"}
              </button>
              {saveStatus === "error" && (
                <span style={{ color: "#fca5a5", fontSize: "0.8rem" }}>Invalid YAML — check syntax</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
