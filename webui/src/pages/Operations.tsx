import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ActionKind,
  AttackOperation,
  AttackPhase,
  Capability,
  api,
  Target,
} from "../api/client";

const PHASES: AttackPhase[] = [
  "recon",
  "initial-access",
  "execution",
  "privilege-escalation",
  "credential-access",
  "discovery",
  "lateral-movement",
  "persistence",
  "impact",
];

const KINDS: ActionKind[] = ["scan", "manual", "pivot"];

const CAPABILITIES: Capability[] = [
  "read-only",
  "state-changing",
  "credential-related",
  "network-pivot",
  "persistence",
];

export default function Operations() {
  const navigate = useNavigate();
  const [operations, setOperations] = useState<AttackOperation[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<AttackOperation | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [newName, setNewName] = useState("");
  const [newObjective, setNewObjective] = useState("");
  const [newEngagement, setNewEngagement] = useState("");
  const [creating, setCreating] = useState(false);

  const [nodeId, setNodeId] = useState("");
  const [nodeTarget, setNodeTarget] = useState("");
  const [nodeLabel, setNodeLabel] = useState("");
  const [addingNode, setAddingNode] = useState(false);

  const [edgeSource, setEdgeSource] = useState("");
  const [edgeDestination, setEdgeDestination] = useState("");
  const [edgeCapabilities, setEdgeCapabilities] = useState<Capability[]>([]);
  const [addingEdge, setAddingEdge] = useState(false);

  const [actionId, setActionId] = useState("");
  const [actionName, setActionName] = useState("");
  const [actionPhase, setActionPhase] = useState<AttackPhase>("recon");
  const [actionKind, setActionKind] = useState<ActionKind>("scan");
  const [actionTarget, setActionTarget] = useState("");
  const [actionPlugin, setActionPlugin] = useState("");
  const [actionRequires, setActionRequires] = useState("");
  const [actionProvides, setActionProvides] = useState("");
  const [addingAction, setAddingAction] = useState(false);

  const [approveActionId, setApproveActionId] = useState<string | null>(null);
  const [approvedBy, setApprovedBy] = useState("");
  const [approveNote, setApproveNote] = useState("");
  const [approving, setApproving] = useState(false);

  const [executeActionId, setExecuteActionId] = useState<string | null>(null);
  const [execCommand, setExecCommand] = useState("");
  const [execOutput, setExecOutput] = useState("");
  const [execTool, setExecTool] = useState("");
  const [executing, setExecuting] = useState(false);
  const [executingAsync, setExecutingAsync] = useState(false);

  const [reportFormat, setReportFormat] = useState<"markdown" | "html">("markdown");
  const [report, setReport] = useState<{ markdown?: string; html?: string } | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);

  const refreshOperations = () => api.listOperations().then(setOperations).catch((e) => setError(String(e)));

  useEffect(() => {
    refreshOperations();
    api.listTargets().then(setTargets).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      setReport(null);
      return;
    }
    setError(null);
    api.getOperation(selected).then(setDetail).catch((e) => setError(String(e)));
    setReport(null);
  }, [selected]);

  const createOperation = (e: FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    api
      .createOperation({ name: newName, objective: newObjective, engagement: newEngagement || null })
      .then((created) => {
        setNewName("");
        setNewObjective("");
        setNewEngagement("");
        return refreshOperations().then(() => setSelected(created.name));
      })
      .catch((e) => setError(String(e)))
      .finally(() => setCreating(false));
  };

  const addNode = (e: FormEvent) => {
    if (!selected) return;
    e.preventDefault();
    setAddingNode(true);
    setError(null);
    api
      .addOperationNode(selected, { node_id: nodeId, target: nodeTarget, label: nodeLabel })
      .then((updated) => {
        setDetail(updated);
        setNodeId("");
        setNodeTarget("");
        setNodeLabel("");
      })
      .catch((e) => setError(String(e)))
      .finally(() => setAddingNode(false));
  };

  const addEdge = (e: FormEvent) => {
    if (!selected) return;
    e.preventDefault();
    setAddingEdge(true);
    setError(null);
    api
      .addOperationEdge(selected, {
        source: edgeSource,
        destination: edgeDestination,
        capabilities: edgeCapabilities.length > 0 ? edgeCapabilities : null,
      })
      .then((updated) => {
        setDetail(updated);
        setEdgeSource("");
        setEdgeDestination("");
        setEdgeCapabilities([]);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setAddingEdge(false));
  };

  const toggleEdgeCapability = (cap: Capability) =>
    setEdgeCapabilities((prev) => (prev.includes(cap) ? prev.filter((c) => c !== cap) : [...prev, cap]));

  const addAction = (e: FormEvent) => {
    if (!selected) return;
    e.preventDefault();
    setAddingAction(true);
    setError(null);
    api
      .addOperationAction(selected, {
        id: actionId,
        name: actionName,
        phase: actionPhase,
        kind: actionKind,
        target: actionTarget,
        plugin: actionKind === "scan" && actionPlugin ? actionPlugin : null,
        requires: actionRequires
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        provides: actionProvides
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      })
      .then((updated) => {
        setDetail(updated);
        setActionId("");
        setActionName("");
        setActionTarget("");
        setActionPlugin("");
        setActionRequires("");
        setActionProvides("");
      })
      .catch((e) => setError(String(e)))
      .finally(() => setAddingAction(false));
  };

  const submitApprove = (e: FormEvent) => {
    if (!selected || !approveActionId) return;
    e.preventDefault();
    setApproving(true);
    setError(null);
    api
      .approveOperationAction(selected, approveActionId, approvedBy, approveNote)
      .then((updated) => {
        setDetail(updated);
        setApproveActionId(null);
        setApprovedBy("");
        setApproveNote("");
      })
      .catch((e) => setError(String(e)))
      .finally(() => setApproving(false));
  };

  const submitExecute = (e: FormEvent) => {
    if (!selected || !executeActionId) return;
    e.preventDefault();
    setExecuting(true);
    setError(null);
    api
      .executeOperationAction(selected, executeActionId, {
        command: execCommand || undefined,
        output: execOutput || undefined,
        tool: execTool || undefined,
      })
      .then((updated) => {
        setDetail(updated);
        setExecuteActionId(null);
        setExecCommand("");
        setExecOutput("");
        setExecTool("");
      })
      .catch((e) => setError(String(e)))
      .finally(() => setExecuting(false));
  };

  const submitExecuteAsync = () => {
    if (!selected || !executeActionId) return;
    setExecutingAsync(true);
    setError(null);
    api
      .executeOperationActionAsync(selected, executeActionId)
      .then(({ job_id }) => {
        navigate(`/operations/${selected}/actions/${executeActionId}/live/${job_id}`);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setExecutingAsync(false));
  };

  const executeTargetAction = executeActionId ? detail?.actions.find((a) => a.id === executeActionId) : undefined;

  const loadReport = () => {
    if (!selected) return;
    setLoadingReport(true);
    setError(null);
    api
      .getOperationReport(selected, reportFormat)
      .then(setReport)
      .catch((e) => setError(String(e)))
      .finally(() => setLoadingReport(false));
  };

  return (
    <div>
      <h2>Operation</h2>
      <p className="muted">
        複数の対象・アクションを攻撃経路（node/edge）として組み立て、承認（approve）を経てから実行します。
        承認前のアクションは実行できません。
      </p>
      {error && <p className="error">{error}</p>}

      <div className="card">
        <h3>新規作成</h3>
        <form onSubmit={createOperation} className="form-grid">
          <label>
            name
            <input value={newName} onChange={(e) => setNewName(e.target.value)} required />
          </label>
          <label>
            objective(任意)
            <input value={newObjective} onChange={(e) => setNewObjective(e.target.value)} />
          </label>
          <label>
            engagement(任意)
            <input value={newEngagement} onChange={(e) => setNewEngagement(e.target.value)} />
          </label>
          <button type="submit" disabled={creating || !newName}>
            {creating ? "作成中..." : "作成"}
          </button>
        </form>
      </div>

      <div className="card">
        <h3>一覧</h3>
        {operations.length === 0 ? (
          <p className="muted">まだOperationがありません。</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th>
                <th>name</th>
                <th>objective</th>
                <th>engagement</th>
                <th>nodes</th>
                <th>actions</th>
              </tr>
            </thead>
            <tbody>
              {operations.map((op) => (
                <tr key={op.name}>
                  <td>
                    <button type="button" onClick={() => setSelected(op.name)}>
                      表示
                    </button>
                  </td>
                  <td>{op.name}</td>
                  <td>{op.objective}</td>
                  <td>{op.engagement ?? "-"}</td>
                  <td>{op.nodes.length}</td>
                  <td>{op.actions.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <>
          <div className="card">
            <h3>{detail.name}</h3>
            <p className="muted">{detail.objective}</p>
            {detail.engagement && <p className="muted">engagement: {detail.engagement}</p>}

            <h4>nodes</h4>
            {detail.nodes.length === 0 ? (
              <p className="muted">まだnodeがありません。</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>id</th>
                    <th>target</th>
                    <th>label</th>
                    <th>state</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.nodes.map((n) => (
                    <tr key={n.id}>
                      <td>{n.id}</td>
                      <td>{n.target}</td>
                      <td>{n.label}</td>
                      <td>{n.state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={addNode} className="option-row">
              <input placeholder="node id" value={nodeId} onChange={(e) => setNodeId(e.target.value)} required />
              <select value={nodeTarget} onChange={(e) => setNodeTarget(e.target.value)} required>
                <option value="" disabled>
                  target選択
                </option>
                {targets.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name}
                  </option>
                ))}
              </select>
              <input placeholder="label(任意)" value={nodeLabel} onChange={(e) => setNodeLabel(e.target.value)} />
              <button type="submit" disabled={addingNode || !nodeId || !nodeTarget}>
                {addingNode ? "追加中..." : "node追加"}
              </button>
            </form>

            <h4>edges</h4>
            {detail.edges.length === 0 ? (
              <p className="muted">まだedgeがありません。</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>source</th>
                    <th>destination</th>
                    <th>relationship</th>
                    <th>capabilities</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.edges.map((e, i) => (
                    <tr key={i}>
                      <td>{e.source}</td>
                      <td>{e.destination}</td>
                      <td>{e.relationship}</td>
                      <td>{e.capabilities.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={addEdge} className="form-grid">
              <label>
                source
                <select value={edgeSource} onChange={(e) => setEdgeSource(e.target.value)} required>
                  <option value="" disabled>
                    node選択
                  </option>
                  {detail.nodes.map((n) => (
                    <option key={n.id} value={n.target}>
                      {n.id} ({n.target})
                    </option>
                  ))}
                </select>
              </label>
              <label>
                destination
                <select value={edgeDestination} onChange={(e) => setEdgeDestination(e.target.value)} required>
                  <option value="" disabled>
                    node選択
                  </option>
                  {detail.nodes.map((n) => (
                    <option key={n.id} value={n.target}>
                      {n.id} ({n.target})
                    </option>
                  ))}
                </select>
              </label>
              <div>
                capabilities(任意)
                {CAPABILITIES.map((cap) => (
                  <label key={cap} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={edgeCapabilities.includes(cap)}
                      onChange={() => toggleEdgeCapability(cap)}
                    />
                    {cap}
                  </label>
                ))}
              </div>
              <button type="submit" disabled={addingEdge || !edgeSource || !edgeDestination}>
                {addingEdge ? "追加中..." : "edge追加"}
              </button>
            </form>

            <h4>actions</h4>
            {detail.actions.length === 0 ? (
              <p className="muted">まだactionがありません。</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>id</th>
                    <th>name</th>
                    <th>phase</th>
                    <th>kind</th>
                    <th>target</th>
                    <th>plugin</th>
                    <th>status</th>
                    <th>run_id</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {detail.actions.map((a) => (
                    <tr key={a.id}>
                      <td>{a.id}</td>
                      <td>{a.name}</td>
                      <td>{a.phase}</td>
                      <td>{a.kind}</td>
                      <td>{a.target}</td>
                      <td>{a.plugin ?? "-"}</td>
                      <td>{a.status}</td>
                      <td>{a.run_id ?? "-"}</td>
                      <td>
                        {a.status === "planned" && (
                          <button
                            type="button"
                            onClick={() => {
                              setApproveActionId(a.id);
                              setExecuteActionId(null);
                            }}
                          >
                            承認
                          </button>
                        )}
                        {a.status === "approved" && (
                          <button
                            type="button"
                            onClick={() => {
                              setExecuteActionId(a.id);
                              setApproveActionId(null);
                            }}
                          >
                            実行
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <form onSubmit={addAction} className="form-grid">
              <label>
                id
                <input value={actionId} onChange={(e) => setActionId(e.target.value)} required />
              </label>
              <label>
                name
                <input value={actionName} onChange={(e) => setActionName(e.target.value)} required />
              </label>
              <label>
                phase
                <select value={actionPhase} onChange={(e) => setActionPhase(e.target.value as AttackPhase)}>
                  {PHASES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                kind
                <select value={actionKind} onChange={(e) => setActionKind(e.target.value as ActionKind)}>
                  {KINDS.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                target
                <select value={actionTarget} onChange={(e) => setActionTarget(e.target.value)} required>
                  <option value="" disabled>
                    target選択
                  </option>
                  {targets.map((t) => (
                    <option key={t.name} value={t.name}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </label>
              {actionKind === "scan" && (
                <label>
                  plugin
                  <input
                    value={actionPlugin}
                    onChange={(e) => setActionPlugin(e.target.value)}
                    placeholder="例: network"
                    required
                  />
                </label>
              )}
              <label>
                requires(任意、カンマ区切り)
                <input value={actionRequires} onChange={(e) => setActionRequires(e.target.value)} />
              </label>
              <label>
                provides(任意、カンマ区切り)
                <input value={actionProvides} onChange={(e) => setActionProvides(e.target.value)} />
              </label>
              <button
                type="submit"
                disabled={addingAction || !actionId || !actionName || !actionTarget}
              >
                {addingAction ? "追加中..." : "action追加"}
              </button>
            </form>

            {approveActionId && (
              <div className="card">
                <h4>action「{approveActionId}」を承認</h4>
                <form onSubmit={submitApprove} className="option-row">
                  <input
                    placeholder="approved_by"
                    value={approvedBy}
                    onChange={(e) => setApprovedBy(e.target.value)}
                    required
                  />
                  <input placeholder="note(任意)" value={approveNote} onChange={(e) => setApproveNote(e.target.value)} />
                  <button type="submit" disabled={approving || !approvedBy}>
                    {approving ? "承認中..." : "承認する"}
                  </button>
                  <button type="button" onClick={() => setApproveActionId(null)}>
                    キャンセル
                  </button>
                </form>
              </div>
            )}

            {executeActionId && executeTargetAction?.kind === "scan" && (
              <div className="card">
                <h4>action「{executeActionId}」を実行</h4>
                <p className="muted">
                  登録済みのplugin/optionsで実際にスキャンが実行されます。バックグラウンドで実行し、
                  完了までライブ進捗画面に遷移します(操作をブロックしません)。
                </p>
                <div>
                  <button type="button" onClick={submitExecuteAsync} disabled={executingAsync}>
                    {executingAsync ? "起動中..." : "実行する"}
                  </button>
                  <button type="button" onClick={() => setExecuteActionId(null)}>
                    キャンセル
                  </button>
                </div>
              </div>
            )}

            {executeActionId && executeTargetAction && executeTargetAction.kind !== "scan" && (
              <div className="card">
                <h4>action「{executeActionId}」を実行</h4>
                <p className="muted">
                  kindがmanual/pivotのため、PownForge自身は何も実行しません。人間が別ツールで
                  実施した結果(output等)をここで記録するだけです。
                </p>
                <form onSubmit={submitExecute} className="form-grid">
                  <label>
                    command(任意)
                    <input value={execCommand} onChange={(e) => setExecCommand(e.target.value)} />
                  </label>
                  <label>
                    output(必須)
                    <input value={execOutput} onChange={(e) => setExecOutput(e.target.value)} required />
                  </label>
                  <label>
                    tool(任意)
                    <input value={execTool} onChange={(e) => setExecTool(e.target.value)} />
                  </label>
                  <div>
                    <button type="submit" disabled={executing}>
                      {executing ? "実行中..." : "実行する"}
                    </button>
                    <button type="button" onClick={() => setExecuteActionId(null)}>
                      キャンセル
                    </button>
                  </div>
                </form>
              </div>
            )}

            <h4>approvals</h4>
            {detail.approvals.length === 0 ? (
              <p className="muted">まだ承認がありません。</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>action_id</th>
                    <th>approved_by</th>
                    <th>approved_at</th>
                    <th>note</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.approvals.map((ap) => (
                    <tr key={ap.id}>
                      <td>{ap.action_id}</td>
                      <td>{ap.approved_by}</td>
                      <td>{ap.approved_at}</td>
                      <td>{ap.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            <h4>レポート</h4>
            <div className="option-row">
              <select value={reportFormat} onChange={(e) => setReportFormat(e.target.value as "markdown" | "html")}>
                <option value="markdown">markdown</option>
                <option value="html">html</option>
              </select>
              <button type="button" onClick={loadReport} disabled={loadingReport}>
                {loadingReport ? "生成中..." : "レポート表示"}
              </button>
              <a href={api.operationReportPdfUrl(detail.name)} target="_blank" rel="noreferrer">
                PDFをダウンロード
              </a>
            </div>
            {report?.markdown && (
              <div>
                <h5>結果(Markdown)</h5>
                <pre>{report.markdown}</pre>
              </div>
            )}
            {report?.html && (
              <div>
                <h5>結果(HTML)</h5>
                <iframe
                  title="operation-report-preview"
                  srcDoc={report.html}
                  sandbox=""
                  style={{ width: "100%", height: "600px", border: "1px solid #ccc", marginTop: "0.5rem" }}
                />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
