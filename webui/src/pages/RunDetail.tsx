import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, RunRecord, Severity } from "../api/client";

// Mirrors reporting/markdown.py's _SEVERITY_ORDER so the web view and the
// generated Markdown report always agree on ordering.
const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export default function RunDetail() {
  const { runId } = useParams<{ runId: string }>();
  const [record, setRecord] = useState<RunRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  useEffect(() => {
    if (!runId) return;
    api.getRun(runId).then(setRecord).catch((e) => setError(String(e)));
  }, [runId]);

  if (error) return <p className="error">{error}</p>;
  if (!record) return <p>loading...</p>;

  const findings = [...record.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );

  const runAnalyze = () => {
    if (!runId) return;
    setAnalyzing(true);
    api
      .analyzeRun(runId)
      .then(setRecord)
      .catch((e) => setError(String(e)))
      .finally(() => setAnalyzing(false));
  };

  return (
    <div>
      <h2>Run {record.run_id}</h2>
      <dl>
        <dt>Target</dt>
        <dd>{record.target}</dd>
        <dt>Plugin</dt>
        <dd>{record.plugin}</dd>
        <dt>Created</dt>
        <dd>{new Date(record.created_at).toLocaleString()}</dd>
        <dt>Return code</dt>
        <dd>{record.evidence.returncode}</dd>
        <dt>Command</dt>
        <dd>
          <code>{record.evidence.command.join(" ")}</code>
        </dd>
      </dl>

      <h3>Findings</h3>
      {findings.length === 0 ? (
        <p className="muted">No findings recorded yet.</p>
      ) : (
        <ul className="findings">
          {findings.map((f, i) => (
            <li key={i} className={`severity-${f.severity}`}>
              <span className="badge">{f.severity}</span>
              <span className="source">{f.source === "ai" ? "AI推定・要確認" : "manual"}</span>
              <strong>{f.title}</strong> — {f.detail}
            </li>
          ))}
        </ul>
      )}

      <h3>
        AI分析{" "}
        <button onClick={runAnalyze} disabled={analyzing}>
          {analyzing ? "分析中..." : "Analyze"}
        </button>
      </h3>
      <p>{record.analysis ?? "pownforge analyze を実行すると、ここに分析草案が表示されます。"}</p>

      <h3>Raw output</h3>
      <pre>{String(record.output.raw_stdout ?? "")}</pre>
    </div>
  );
}
