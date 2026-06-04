import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

// Kill-chain zones, left -> right. Drives both node color and column layout.
const ZONE_ORDER = ["external", "edge", "dmz", "corp"];
const ZONE_COLOR = {
  external: "#5b6b8c",
  edge: "#2e7dd1",
  dmz: "#c9952b",
  corp: "#c0392b",
};
const ZONE_LABEL = {
  external: "EXTERNAL",
  edge: "EDGE / CDN",
  dmz: "DMZ",
  corp: "CORP",
};

// Lay nodes out in zone columns so the path from internet -> corp-db reads
// left to right. Deterministic positions keep the demo visually stable.
function computePositions(nodes) {
  const byZone = {};
  for (const n of nodes) (byZone[n.zone] ??= []).push(n);
  const colGap = 240;
  const rowGap = 110;
  const pos = {};
  ZONE_ORDER.forEach((zone, col) => {
    const group = byZone[zone] ?? [];
    const offset = ((group.length - 1) * rowGap) / 2;
    group.forEach((n, row) => {
      pos[n.id] = { x: col * colGap, y: row * rowGap - offset };
    });
  });
  return pos;
}

export default function Topology({ snapshot }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current || !snapshot) return;

    const positions = computePositions(snapshot.nodes);
    const elements = [
      ...snapshot.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label ?? n.id,
          zone: n.zone,
          goal: n.is_goal ? 1 : 0,
        },
        position: positions[n.id],
      })),
      ...snapshot.edges.map((e) => ({
        data: {
          id: `${e.source}->${e.target}`,
          source: e.source,
          target: e.target,
          etype: e.type,
          locked: e.requires_cred ? 1 : 0,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (el) => ZONE_COLOR[el.data("zone")] ?? "#888",
            label: "data(label)",
            color: "#e6ecff",
            "font-size": 11,
            "text-valign": "bottom",
            "text-margin-y": 6,
            "text-wrap": "wrap",
            "text-max-width": 130,
            width: 38,
            height: 38,
            "border-width": 2,
            "border-color": "#0b0f1a",
          },
        },
        {
          selector: "node[goal = 1]",
          style: {
            "border-width": 4,
            "border-color": "#ffd24d",
            width: 48,
            height: 48,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#3a4a6b",
            "target-arrow-color": "#3a4a6b",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            opacity: 0.8,
          },
        },
        {
          selector: 'edge[etype = "trust"]',
          style: { "line-style": "dashed", "line-color": "#6f8fc0", "target-arrow-color": "#6f8fc0" },
        },
        {
          selector: "edge[locked = 1]",
          style: { "line-color": "#ffd24d", "target-arrow-color": "#ffd24d", width: 3 },
        },
      ],
      layout: { name: "preset" },
      minZoom: 0.3,
      maxZoom: 2.5,
    });

    cy.fit(undefined, 60);

    return () => cy.destroy();
  }, [snapshot]);

  return (
    <div className="topology">
      <div ref={containerRef} className="topology__canvas" />
      <div className="legend">
        <h4>Zones</h4>
        {ZONE_ORDER.map((z) => (
          <div className="legend__row" key={z}>
            <span className="legend__swatch" style={{ background: ZONE_COLOR[z] }} />
            {ZONE_LABEL[z]}
          </div>
        ))}
        <h4 style={{ marginTop: 8 }}>Edges</h4>
        <div className="legend__row">
          <span className="legend__swatch" style={{ background: "#ffd24d" }} />
          credential-locked shortcut
        </div>
      </div>
    </div>
  );
}
