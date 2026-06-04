import { useEffect, useState } from "react";
import Topology from "./Topology.jsx";

export default function App() {
  const [snapshot, setSnapshot] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch("/topology")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setSnapshot)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <div className="app">
      <header className="app__header">
        <h1>PROVING GRID</h1>
        <span className="sub">
          digital-twin cyber range · goal: exfiltrate{" "}
          {snapshot?.meta?.goal_node ?? "…"}
        </span>
      </header>
      <div className="app__body">
        {error && (
          <div className="status">
            Could not load topology: {error}. Is the backend running on :8000?
          </div>
        )}
        {!error && !snapshot && <div className="status">Loading topology…</div>}
        {snapshot && <Topology snapshot={snapshot} />}
      </div>
    </div>
  );
}
