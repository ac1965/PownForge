import { AttackEdge, AttackNode, AttackNodeState, Capability, OperationAction } from "../api/client";

// AttackGraph renders an AttackOperation's nodes/edges as a directed
// graph — the "攻撃経路" that Operations.tsx otherwise only shows as two
// separate tables. Pure SVG, no charting/graph library: the webui has
// none today (react/react-dom/react-router-dom only), and these graphs
// are small (a handful of hosts/pivots per operation), so a from-scratch
// layered layout is simpler than adding a dependency for it.
//
// AttackEdge.source/destination and OperationAction.target all reference
// AttackNode.target (the scope target name), not AttackNode.id --
// confirmed against core/operation/service.py's add_edge, which checks
// AttackGraph.has_target(source/destination). This component keys its
// layout and lookups the same way.

interface Props {
  nodes: AttackNode[];
  edges: AttackEdge[];
  actions: OperationAction[];
}

const STATE_COLOR: Record<AttackNodeState, string> = {
  known: "#95a5a6",
  candidate: "#7f8c8d",
  planned: "#3498db",
  approved: "#f1c40f",
  running: "#e67e22",
  succeeded: "#27ae60",
  failed: "#c0392b",
  skipped: "#bdc3c7",
};

const ACTION_COLOR: Record<OperationAction["status"], string> = {
  planned: "#3498db",
  approved: "#f1c40f",
  completed: "#27ae60",
  rejected: "#c0392b",
};

// Capabilities that represent a real consequence for the target (data
// changed, credentials obtained, a foothold persisted) as opposed to
// read-only/network-pivot which are just observation or movement --
// mirrors how core/operation/model.py's provided_tags() distinguishes
// "what an action provides" from mere reconnaissance.
const IMPACT_CAPABILITIES = new Set<Capability>(["state-changing", "credential-related", "persistence"]);
const IMPACT_COLOR = "#c0392b";

const COL_WIDTH = 210;
const ROW_HEIGHT = 100;
const MARGIN = 60;
const NODE_W = 150;
const NODE_H = 60;

interface Position {
  x: number;
  y: number;
}

// layoutByTarget assigns each node's target a (layer, position-in-layer)
// via a shortest-hop-distance BFS from every node with no incoming edge
// (or, if every node has one -- i.e. a cycle with no clear root -- from
// every node, so a cycle still renders instead of producing an empty
// layout). Plain BFS (never revisiting a target once layered) rather
// than a longest-path algorithm, specifically so a cycle can't loop
// forever recomputing layers -- good enough for a readable diagram of a
// few nodes, not attempting to be an optimal DAG layout.
function layoutByTarget(nodes: AttackNode[], edges: AttackEdge[]): Map<string, Position> {
  const targets = [...new Set(nodes.map((n) => n.target))];
  const outgoing = new Map<string, string[]>(targets.map((t) => [t, []]));
  const hasIncoming = new Set<string>();
  for (const e of edges) {
    if (outgoing.has(e.source)) outgoing.get(e.source)!.push(e.destination);
    if (targets.includes(e.destination)) hasIncoming.add(e.destination);
  }

  const roots = targets.filter((t) => !hasIncoming.has(t));
  const queue = roots.length > 0 ? [...roots] : [...targets];
  const layerOf = new Map<string, number>(queue.map((t) => [t, 0]));

  while (queue.length > 0) {
    const t = queue.shift()!;
    const layer = layerOf.get(t)!;
    for (const next of outgoing.get(t) ?? []) {
      if (!layerOf.has(next)) {
        layerOf.set(next, layer + 1);
        queue.push(next);
      }
    }
  }
  // Any target BFS never reached (e.g. only incoming edges from another
  // unreached target in a disjoint cycle) still needs a position.
  for (const t of targets) if (!layerOf.has(t)) layerOf.set(t, 0);

  const byLayer = new Map<number, string[]>();
  for (const [t, layer] of layerOf) {
    if (!byLayer.has(layer)) byLayer.set(layer, []);
    byLayer.get(layer)!.push(t);
  }

  const positions = new Map<string, Position>();
  for (const [layer, layerTargets] of byLayer) {
    layerTargets.forEach((t, i) => {
      positions.set(t, { x: MARGIN + layer * COL_WIDTH, y: MARGIN + i * ROW_HEIGHT });
    });
  }
  return positions;
}

interface Impact {
  provides: string[];
  isImpactful: boolean;
}

// nodeImpact answers "what did compromising this target actually get the
// attacker" -- mirrors core/operation/model.py's provided_tags(), scoped
// to one target's completed actions, plus a broader isImpactful flag for
// nodes that reached (or are reaching for) real consequence even before
// anything is confirmed provided yet.
function nodeImpact(target: string, actionsByTarget: Map<string, OperationAction[]>, outgoingByTarget: Map<string, AttackEdge[]>): Impact {
  const targetActions = actionsByTarget.get(target) ?? [];
  const completed = targetActions.filter((a) => a.status === "completed");
  const provides = [...new Set(completed.flatMap((a) => a.provides))];
  const outgoing = outgoingByTarget.get(target) ?? [];
  const isImpactful =
    targetActions.some((a) => a.phase === "impact") ||
    completed.some((a) => a.capabilities.some((c) => IMPACT_CAPABILITIES.has(c))) ||
    outgoing.some((e) => e.capabilities.some((c) => IMPACT_CAPABILITIES.has(c))) ||
    provides.length > 0;
  return { provides, isImpactful };
}

export default function AttackGraph({ nodes, edges, actions }: Props) {
  if (nodes.length === 0) return null;

  const positions = layoutByTarget(nodes, edges);
  // First node per target wins if more than one AttackNode shares a
  // target (structurally possible -- add_node only rejects a reused id,
  // not a reused target -- though operations built through the normal
  // CLI/Web flows won't do this).
  const nodeByTarget = new Map<string, AttackNode>();
  for (const n of nodes) if (!nodeByTarget.has(n.target)) nodeByTarget.set(n.target, n);

  const actionsByTarget = new Map<string, OperationAction[]>();
  for (const a of actions) {
    if (!actionsByTarget.has(a.target)) actionsByTarget.set(a.target, []);
    actionsByTarget.get(a.target)!.push(a);
  }

  const outgoingByTarget = new Map<string, AttackEdge[]>();
  for (const e of edges) {
    if (!outgoingByTarget.has(e.source)) outgoingByTarget.set(e.source, []);
    outgoingByTarget.get(e.source)!.push(e);
  }

  const maxX = Math.max(...[...positions.values()].map((p) => p.x)) + NODE_W + MARGIN;
  const maxY = Math.max(...[...positions.values()].map((p) => p.y)) + NODE_H + MARGIN;

  return (
    <div className="attack-graph-wrap">
      <svg className="attack-graph" width={maxX} height={maxY} viewBox={`0 0 ${maxX} ${maxY}`}>
        <defs>
          {/* currentColor inside <marker> content resolves against the
              marker element's own position in the DOM (inside <defs>),
              not the <line> that references it via markerEnd -- a well
              known SVG quirk -- so this uses a literal color matching
              .attack-graph-edges's `color` instead of relying on
              inheritance here. */}
          <marker id="attack-graph-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="#8888" />
          </marker>
          <marker id="attack-graph-arrow-impact" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill={IMPACT_COLOR} />
          </marker>
        </defs>

        <g className="attack-graph-edges">
          {edges.map((e, i) => {
            const from = positions.get(e.source);
            const to = positions.get(e.destination);
            if (!from || !to) return null; // shouldn't happen; domain requires both endpoints to be existing nodes
            const isImpactEdge = e.capabilities.some((c) => IMPACT_CAPABILITIES.has(c));
            const x1 = from.x + NODE_W;
            const y1 = from.y + NODE_H / 2;
            const x2 = to.x;
            const y2 = to.y + NODE_H / 2;
            const midX = (x1 + x2) / 2;
            const midY = (y1 + y2) / 2;
            return (
              <g key={`${e.source}->${e.destination}-${i}`} className="attack-graph-edge">
                <line
                  x1={x1}
                  y1={y1}
                  x2={x2}
                  y2={y2}
                  stroke={isImpactEdge ? IMPACT_COLOR : "currentColor"}
                  strokeWidth={isImpactEdge ? 2.5 : 1.5}
                  markerEnd={isImpactEdge ? "url(#attack-graph-arrow-impact)" : "url(#attack-graph-arrow)"}
                />
                <text x={midX} y={midY - 6} textAnchor="middle" className="attack-graph-edge-label">
                  {e.relationship}
                  {e.attack_technique_ids.length > 0 ? ` (${e.attack_technique_ids.join(", ")})` : ""}
                </text>
              </g>
            );
          })}
        </g>

        {[...nodeByTarget.entries()].map(([target, n]) => {
          const pos = positions.get(target);
          if (!pos) return null;
          const nodeActions = actionsByTarget.get(target) ?? [];
          const { provides, isImpactful } = nodeImpact(target, actionsByTarget, outgoingByTarget);
          const impactText = provides.length > 0 ? provides.join(", ") : isImpactful ? "確認要" : null;
          return (
            <g key={n.id} transform={`translate(${pos.x}, ${pos.y})`} className="attack-graph-node">
              {isImpactful && (
                <rect
                  x={-3}
                  y={-3}
                  width={NODE_W + 6}
                  height={NODE_H + 6}
                  rx={9}
                  fill="none"
                  stroke={IMPACT_COLOR}
                  strokeWidth={2}
                  strokeDasharray="4 3"
                />
              )}
              <rect width={NODE_W} height={NODE_H} rx={6} fill={STATE_COLOR[n.state]} fillOpacity={0.18} stroke={STATE_COLOR[n.state]} strokeWidth={2}>
                <title>
                  {n.label || n.id} ({target}) -- state: {n.state}
                  {n.attack_technique_ids.length > 0 ? `, ATT&CK: ${n.attack_technique_ids.join(", ")}` : ""}
                  {isImpactful ? `, impact: ${impactText}` : ""}
                </title>
              </rect>
              {isImpactful && (
                <text x={NODE_W - 14} y={-6} className="attack-graph-node-impact-badge" textAnchor="middle">
                  ⚠
                </text>
              )}
              <text x={8} y={18} className="attack-graph-node-label">
                {n.label || n.id}
              </text>
              <text x={8} y={34} className="attack-graph-node-target">
                {target}
              </text>
              {n.attack_technique_ids.length > 0 && (
                <text x={8} y={46} className="attack-graph-node-attck">
                  {n.attack_technique_ids.join(", ")}
                </text>
              )}
              {impactText && (
                <text x={8} y={NODE_H - 2} className="attack-graph-node-impact">
                  {impactText}
                </text>
              )}
              {nodeActions.map((a, i) => (
                <circle key={a.id} cx={NODE_W - 10 - i * 12} cy={10} r={4} fill={ACTION_COLOR[a.status]}>
                  <title>
                    {a.name} ({a.phase}/{a.kind}) -- {a.status}
                  </title>
                </circle>
              ))}
            </g>
          );
        })}
      </svg>
      <p className="attack-graph-legend muted">
        node枠線の色 = state（known/candidate/planned/approved/running/succeeded/failed/skipped）。
        右上の丸 = そのtargetに対するaction（色はstatus）。
        赤い破線の外枠と⚠ = そのtargetへの侵害が実害（state-changing/credential-related/persistence等）につながったこと。
        下部の赤文字 = 実際に得られたもの（provides）、まだ確定していない場合は「確認要」。
        赤い太線のedge = その経路の悪用が実害に直結すること。ホバーで詳細を表示します。
      </p>
    </div>
  );
}
