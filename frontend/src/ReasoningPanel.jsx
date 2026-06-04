export default function ReasoningPanel({ steps = [] }) {
  return (
    <div className="panel reasoning-panel">
      <h2>Attacker reasoning</h2>
      {steps.length === 0 ? (
        <p className="reasoning-placeholder">Waiting for attacker…</p>
      ) : (
        <ol style={{ margin: 0, paddingLeft: 18, fontSize: "0.85rem" }}>
          {steps.map((step, i) => (
            <li key={i} style={{ marginBottom: 8 }}>
              {typeof step === "string" ? step : step.text || JSON.stringify(step)}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
