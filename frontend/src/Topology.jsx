import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";

cytoscape.use(dagre);

const NEUTRAL_EDGE = "#64748b";
const COMPROMISED_EDGE = "#ef4444";

/** Trust shown as line style, not color — colors reserved for compromised paths. */
const TRUST_LINE = {
  high: "solid",
  medium: "dashed",
  low: "dotted",
};

function nodeColor(node) {
  if (node.exfiltrated) return "#f97316";
  if (node.compromised) return "#ef4444";
  if (node.isolated) return "#9ca3af";
  return "#3b82f6";
}

function edgeAppearance(edge, nodesById) {
  const src = nodesById[edge.source];
  const tgt = nodesById[edge.target];
  const trustStyle = TRUST_LINE[edge.trust] || TRUST_LINE.medium;

  if (edge.active === false) {
    return {
      lineColor: "#475569",
      lineStyle: "dotted",
      width: 1,
      edgeOpacity: 0.25,
    };
  }

  // Outbound path from a compromised host (attack lateral movement)
  if (src?.compromised) {
    return {
      lineColor: COMPROMISED_EDGE,
      lineStyle: "solid",
      width: 3,
      edgeOpacity: 1,
    };
  }

  return {
    lineColor: NEUTRAL_EDGE,
    lineStyle: trustStyle,
    width: 2,
    edgeOpacity: 1,
  };
}

export default function Topology({ snapshot }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [tooltip, setTooltip] = useState(null);

  useEffect(() => {
    if (!snapshot || !containerRef.current) return;

    const nodesById = Object.fromEntries(
      snapshot.nodes.map((n) => [n.id, n])
    );

    const elements = [
      ...snapshot.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.id,
          bg: nodeColor(n),
          services: (n.services || []).join(", ") || "(none)",
          vulns:
            (n.modeled_vulns || [])
              .map((v) => `${v.id}: ${v.description || v.technique}`)
              .join("\n") || "(none)",
        },
      })),
      ...snapshot.edges.map((e, i) => {
        const appearance = edgeAppearance(e, nodesById);
        return {
          data: {
            id: `${e.source}-${e.target}-${i}`,
            source: e.source,
            target: e.target,
            trust: e.trust || "medium",
            active: e.active,
            ...appearance,
          },
        };
      }),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-valign": "bottom",
            "text-margin-y": 6,
            color: "#e7ecf3",
            "font-size": 10,
            width: 36,
            height: 36,
            "background-color": "data(bg)",
            "border-width": 2,
            "border-color": "#1e293b",
          },
        },
        {
          selector: "edge",
          style: {
            width: "data(width)",
            "line-color": "data(lineColor)",
            "line-style": "data(lineStyle)",
            "target-arrow-color": "data(lineColor)",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            opacity: "data(edgeOpacity)",
          },
        },
      ],
      layout: {
        name: "dagre",
        rankDir: "TB",
        nodeSep: 40,
        rankSep: 60,
      },
    });

    cy.on("mouseover", "node", (evt) => {
      const node = evt.target.data();
      const pos = evt.target.renderedPosition();
      setTooltip({
        x: pos.x,
        y: pos.y,
        id: node.id,
        services: node.services,
        vulns: node.vulns,
      });
    });

    cy.on("mouseout", "node", () => setTooltip(null));

    cy.on("mouseover", "edge", (evt) => {
      const edge = evt.target.data();
      const pos = evt.target.midpoint();
      setTooltip({
        x: pos.x,
        y: pos.y,
        id: `${edge.source} → ${edge.target}`,
        services: `Trust: ${edge.trust} (${edge.lineStyle})`,
        vulns: edge.lineColor === COMPROMISED_EDGE
          ? "Compromised path (outbound from owned host)"
          : "Normal path",
      });
    });

    cy.on("mouseout", "edge", () => setTooltip(null));

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [snapshot]);

  return (
    <div className="topology-wrap">
      <div ref={containerRef} className="topology-cy" />
      {tooltip && (
        <div
          className="node-tooltip"
          style={{ left: tooltip.x + 12, top: tooltip.y + 12 }}
        >
          <strong>{tooltip.id}</strong>
          <div>
            <em>Services:</em> {tooltip.services}
          </div>
          <div style={{ marginTop: 6, whiteSpace: "pre-wrap" }}>
            <em>Vulns:</em>
            {"\n"}
            {tooltip.vulns}
          </div>
        </div>
      )}
    </div>
  );
}
