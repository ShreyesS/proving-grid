import { useEffect, useRef } from "react";

// MITRE technique -> short label + accent color, so a judge sees the kill chain.
const TECHNIQUE_STYLE = {
  recon: { label: "RECON", color: "#64748b" },
  "initial-access": { label: "INITIAL ACCESS", color: "#3b82f6" },
  "lateral-movement": { label: "LATERAL MOVEMENT", color: "#a855f7" },
  "privilege-escalation": { label: "PRIV ESC", color: "#f59e0b" },
  "credential-access": { label: "CREDENTIAL ACCESS", color: "#eab308" },
  "defense-evasion": { label: "DEFENSE EVASION", color: "#8b5cf6" },
  collection: { label: "COLLECTION", color: "#14b8a6" },
  exfiltration: { label: "EXFILTRATION", color: "#ef4444" },
};

// Techniques come from the topology (underscores) or the tools (hyphens) —
// normalize so the tag renders either way.
function techStyle(technique) {
  return TECHNIQUE_STYLE[(technique || "").replace(/_/g, "-")];
}

function Tag({ text, color, title }) {
  return (
    <span
      title={title}
      style={{
        display: "inline-block",
        fontSize: "0.62rem",
        fontWeight: 700,
        letterSpacing: "0.04em",
        padding: "1px 6px",
        borderRadius: 4,
        background: `${color}22`,
        color,
        border: `1px solid ${color}55`,
        whiteSpace: "nowrap",
      }}
    >
      {text}
    </span>
  );
}

function Step({ s }) {
  if (s.kind === "finding") {
    return (
      <div
        style={{
          margin: "10px 0 4px",
          padding: "8px 10px",
          borderRadius: 6,
          background: "rgba(74, 222, 128, 0.10)",
          border: "1px solid rgba(74, 222, 128, 0.4)",
          fontSize: "0.8rem",
        }}
      >
        <div style={{ color: "#4ade80", fontWeight: 700, marginBottom: 4 }}>
          ✓ ATTACK PATH DISCOVERED
        </div>
        <div style={{ color: "#cbd5e1", lineHeight: 1.5 }}>
          {(s.exposures_chained || []).join("  →  ") || s.text}
        </div>
      </div>
    );
  }

  if (s.kind === "detection") {
    return (
      <div
        style={{
          margin: "8px 0",
          padding: "8px 10px",
          borderRadius: 6,
          background: "rgba(239, 68, 68, 0.12)",
          border: "1px solid rgba(239, 68, 68, 0.5)",
          color: "#fecaca",
          fontSize: "0.8rem",
          lineHeight: 1.45,
          fontWeight: 600,
        }}
      >
        {s.text}
      </div>
    );
  }

  if (s.kind === "defense") {
    return (
      <div
        style={{
          margin: "8px 0",
          padding: "8px 10px",
          borderRadius: 6,
          background: "rgba(56, 189, 248, 0.10)",
          border: "1px solid rgba(56, 189, 248, 0.45)",
          color: "#bae6fd",
          fontSize: "0.8rem",
          lineHeight: 1.45,
        }}
      >
        {s.text}
      </div>
    );
  }

  if (s.kind === "error") {
    return (
      <div style={{ color: "#fca5a5", fontSize: "0.8rem", margin: "6px 0" }}>
        {s.text}
      </div>
    );
  }

  const tech = techStyle(s.technique);
  return (
    <div
      style={{
        margin: "0 0 10px",
        paddingBottom: 10,
        borderBottom: "1px solid #222c3c",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, flexWrap: "wrap" }}>
        <span style={{ color: "#64748b", fontWeight: 700, fontSize: "0.72rem" }}>
          STEP {s.step}
        </span>
        {tech && <Tag text={tech.label} color={tech.color} />}
        {s.tool && (
          <span style={{ color: "#8b9cb3", fontSize: "0.72rem", fontFamily: "ui-monospace, monospace" }}>
            {s.tool}
            {s.target ? ` → ${s.target}` : ""}
          </span>
        )}
      </div>

      <div style={{ color: "#dbe4f0", fontSize: "0.82rem", lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
        {s.thought}
        {s.streaming && <span className="rp-cursor">▌</span>}
      </div>

      {s.exposure && (
        <div style={{ marginTop: 5 }}>
          <Tag
            text={`exploiting: ${s.exposure}`}
            color="#f59e0b"
            title="The specific CVE / credential / trust edge being abused"
          />
        </div>
      )}

      {s.observation && !s.streaming && (
        <div
          style={{
            marginTop: 5,
            fontSize: "0.76rem",
            color: s.ok ? "#86efac" : "#fca5a5",
            fontFamily: "ui-monospace, monospace",
          }}
        >
          → {s.observation}
        </div>
      )}
    </div>
  );
}

export default function ReasoningPanel({ steps = [] }) {
  const endRef = useRef(null);

  // Auto-scroll to the latest reasoning as it streams in.
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [steps]);

  return (
    <div className="panel reasoning-panel">
      <style>{`@keyframes rpblink{0%,49%{opacity:1}50%,100%{opacity:0}}
        .rp-cursor{animation:rpblink 1s steps(1) infinite;color:#4ade80;margin-left:1px}`}</style>
      <h2>Attacker reasoning</h2>
      {steps.length === 0 ? (
        <p className="reasoning-placeholder">Waiting for attacker…</p>
      ) : (
        <div style={{ fontSize: "0.85rem" }}>
          {steps.map((s, i) => (
            <Step key={`${s.kind}-${s.step}-${i}`} s={s} />
          ))}
          <div ref={endRef} />
        </div>
      )}
    </div>
  );
}
