// Bottom-left HUD: after a run, offer to patch the CVEs that attack used,
// and reveal exactly what was patched where. The "harden it → re-run → prove
// it's closed" loop, right over the topology.

const CVE_RE = /^[A-Z][A-Z0-9-]+$/; // CVE-ish exposure ids (skip creds / trust:.. / data)

export default function PatchHud({ lastRun, hardened, patchedWhere, onPatch, onRestore }) {
  const cves = (lastRun?.exposures || []).filter((e) => CVE_RE.test(e));
  const hasSomething = (lastRun && cves.length > 0) || (hardened && hardened.length > 0);
  if (!hasSomething) return null;

  const tag = lastRun?.evaded_defense
    ? { text: "EVADED", color: "#ef4444" }
    : lastRun?.outcome === "contained"
    ? { text: "CONTAINED", color: "#38bdf8" }
    : lastRun?.reached_goal
    ? { text: "BREACHED", color: "#f59e0b" }
    : null;

  return (
    <div
      style={{
        position: "absolute",
        bottom: 14,
        left: 14,
        width: 320,
        maxWidth: "46%",
        background: "rgba(15, 20, 25, 0.94)",
        border: "1px solid #2a3544",
        borderRadius: 8,
        padding: "10px 12px",
        zIndex: 20,
        boxShadow: "0 6px 20px rgba(0,0,0,0.45)",
        fontSize: "0.78rem",
        color: "#cbd5e1",
      }}
    >
      {lastRun && cves.length > 0 && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <strong style={{ color: "#e7ecf3" }}>Last attack</strong>
            {tag && (
              <span style={{
                fontSize: "0.56rem", fontWeight: 700, color: tag.color,
                border: `1px solid ${tag.color}66`, background: `${tag.color}1a`,
                borderRadius: 4, padding: "1px 5px",
              }}>{tag.text}</span>
            )}
          </div>
          <div style={{ fontFamily: "ui-monospace, monospace", fontSize: "0.68rem", color: "#9fb0c8", lineHeight: 1.35, marginBottom: 8 }}>
            {lastRun.chain}
          </div>
          <button
            onClick={() => onPatch(cves)}
            title="Patch the CVEs this attack exploited, then re-run to prove it"
            style={{
              width: "100%", padding: "6px 0", fontWeight: 700, fontSize: "0.78rem",
              color: "#052e16", background: "#4ade80", border: "none",
              borderRadius: 6, cursor: "pointer", letterSpacing: "0.02em",
            }}
          >
            🛡 Patch this attack’s {cves.length} CVE{cves.length === 1 ? "" : "s"}
          </button>
        </>
      )}

      {hardened && hardened.length > 0 && (
        <div style={{ marginTop: lastRun && cves.length > 0 ? 10 : 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <strong style={{ color: "#86efac", fontSize: "0.72rem" }}>
              ✓ Patched ({hardened.length})
            </strong>
            <button onClick={onRestore} style={{
              fontSize: "0.6rem", color: "#8b9cb3", background: "transparent",
              border: "1px solid #8b9cb3", borderRadius: 4, padding: "1px 7px", cursor: "pointer",
            }}>Restore</button>
          </div>
          <div style={{ marginTop: 4, display: "flex", flexDirection: "column", gap: 2 }}>
            {hardened.map((v) => (
              <div key={v} style={{ fontSize: "0.68rem", color: "#bfe9cf" }}>
                <span style={{ fontFamily: "ui-monospace, monospace" }}>{v}</span>
                {patchedWhere?.[v] && (
                  <span style={{ color: "#7689a6" }}> → {patchedWhere[v]}</span>
                )}
              </div>
            ))}
          </div>
          <div style={{ marginTop: 6, fontSize: "0.64rem", color: "#7689a6", fontStyle: "italic" }}>
            Re-run to verify the attack is closed.
          </div>
        </div>
      )}
    </div>
  );
}
