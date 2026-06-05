// The cross-run coverage / agent-performance report — fed by memory.
// Each run adds a discovered path; the eval fills it in bulk.

function Stat({ label, value, color }) {
  return (
    <div style={{ textAlign: "center", flex: 1 }}>
      <div style={{ fontSize: "1.3rem", fontWeight: 700, color: color || "#e7ecf3" }}>
        {value}
      </div>
      <div style={{ fontSize: "0.62rem", color: "#8b9cb3", textTransform: "uppercase", letterSpacing: "0.04em" }}>
        {label}
      </div>
    </div>
  );
}

function PathRow({ p }) {
  const tag = p.evaded_defense
    ? { text: "EVADED", color: "#ef4444" }
    : p.outcome === "contained"
    ? { text: "CONTAINED", color: "#38bdf8" }
    : p.reached_goal
    ? { text: "BREACHED", color: "#f59e0b" }
    : { text: "BLOCKED", color: "#64748b" };
  return (
    <div style={{ padding: "6px 0", borderBottom: "1px solid #222c3c" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: "0.72rem", fontFamily: "ui-monospace, monospace", color: "#cbd5e1", lineHeight: 1.3 }}>
          {p.chain}
        </span>
        <span style={{
          fontSize: "0.58rem", fontWeight: 700, color: tag.color,
          border: `1px solid ${tag.color}66`, background: `${tag.color}1a`,
          borderRadius: 4, padding: "1px 5px", whiteSpace: "nowrap",
        }}>
          {tag.text}
        </span>
      </div>
      {p.exposures?.length > 0 && (
        <div style={{ fontSize: "0.64rem", color: "#7689a6", marginTop: 2 }}>
          {p.exposures.join(" · ")}
        </div>
      )}
    </div>
  );
}

export default function CoveragePanel({ coverage, evalProgress }) {
  const c = coverage;
  return (
    <div className="panel" style={{ minHeight: 0, display: "flex", flexDirection: "column" }}>
      <h2>Attack-path coverage</h2>
      {evalProgress && (
        <div style={{ fontSize: "0.7rem", color: "#fbbf24", marginBottom: 6 }}>
          Eval running… {evalProgress.run}/{evalProgress.of}
        </div>
      )}
      {!c || c.total_runs === 0 ? (
        <p className="reasoning-placeholder">
          No runs yet — hit Run, or Eval ×N to measure the agent.
        </p>
      ) : (
        <>
          <div style={{ display: "flex", gap: 4, margin: "4px 0 10px" }}>
            <Stat label="distinct paths" value={c.distinct_paths} color="#a78bfa" />
            <Stat label="evaded def." value={c.evaded_defense} color="#ef4444" />
            <Stat label="contained" value={c.contained} color="#38bdf8" />
            <Stat label="med. detect" value={c.median_detection_step ?? "—"} color="#e7ecf3" />
          </div>
          <div style={{ fontSize: "0.62rem", color: "#8b9cb3", marginBottom: 4 }}>
            {c.total_runs} run{c.total_runs === 1 ? "" : "s"} · {c.breached} breached
          </div>
          <div style={{ overflow: "auto", flex: 1 }}>
            {c.paths.map((p, i) => <PathRow key={i} p={p} />)}
          </div>
        </>
      )}
    </div>
  );
}
