export default function Scoreboard({ snapshot }) {
  if (!snapshot) {
    return (
      <div className="panel">
        <h2>Scoreboard</h2>
        <p className="reasoning-placeholder">Loading state…</p>
      </div>
    );
  }

  const compromised = snapshot.nodes.filter((n) => n.compromised).length;
  const isolated = snapshot.nodes.filter((n) => n.isolated).length;
  const integrity = snapshot.mission_integrity ?? 100;

  return (
    <div className="panel">
      <h2>Scoreboard</h2>
      <div className="scoreboard-metric">{integrity}%</div>
      <div style={{ fontSize: "0.8rem", color: "#8b9cb3" }}>Mission integrity</div>
      <ul className="scoreboard-stats">
        <li>Nodes compromised: {compromised}</li>
        <li>Nodes isolated: {isolated}</li>
        <li>Total nodes: {snapshot.nodes.length}</li>
      </ul>
    </div>
  );
}
