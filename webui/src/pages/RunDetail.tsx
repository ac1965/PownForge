import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, EvidenceVerification, Finding, FindingStatus, RunRecord, Severity } from "../api/client";

// Mirrors reporting/markdown.py's _SEVERITY_ORDER so the web view and the
// generated Markdown report always agree on ordering.
const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const STATUS_SECTIONS: [FindingStatus, string][] = [
  ["confirmed", "確認済み"],
  ["needs-review", "要確認"],
  ["false-positive", "誤検知として却下"],
];

const STATUS_LABELS: Record<FindingStatus, string> = {
  confirmed: "確認済みにする",
  "needs-review": "要確認に戻す",
  "false-positive": "誤検知にする",
};

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export default function RunDetail() {
  const { runId } = useParams<{ runId: string }>();
  const [record, setRecord] = useState<RunRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [reviewingId, setReviewingId] = useState<string | null>(null);
  const [verification, setVerification] = useState<EvidenceVerification | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    if (!runId) return;
    api.getRun(runId).then(setRecord).catch((e) => setError(String(e)));
  }, [runId]);

  if (error) return <p className="error">{error}</p>;
  if (!record) return <p>loading...</p>;

  const runAnalyze = () => {
    if (!runId) return;
    setAnalyzing(true);
    api
      .analyzeRun(runId)
      .then(setRecord)
      .catch((e) => setError(String(e)))
      .finally(() => setAnalyzing(false));
  };

  const runVerify = () => {
    if (!runId) return;
    setVerifying(true);
    api
      .verifyRun(runId)
      .then(setVerification)
      .catch((e) => setError(String(e)))
      .finally(() => setVerifying(false));
  };

  const reviewFinding = (findingId: string, status: FindingStatus) => {
    if (!runId) return;
    setReviewingId(findingId);
    api
      .reviewFinding(runId, findingId, status)
      .then(setRecord)
      .catch((e) => setError(String(e)))
      .finally(() => setReviewingId(null));
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
        <dt>Tool version</dt>
        <dd>{record.evidence.tool_version ?? "unknown"}</dd>
        <dt>stdout sha256</dt>
        <dd>
          <code>{record.evidence.stdout_sha256}</code>
        </dd>
        <dt>stderr sha256</dt>
        <dd>
          <code>{record.evidence.stderr_sha256}</code>
        </dd>
      </dl>

      <p>
        <button onClick={runVerify} disabled={verifying}>
          {verifying ? "検証中..." : "Verify evidence"}
        </button>{" "}
        {verification && (
          <span className={verification.ok ? "verify-ok" : "verify-mismatch"}>
            {verification.ok
              ? "OK: 保存されたoutputはハッシュと一致します"
              : "MISMATCH: outputがハッシュと一致しません（同じファイルを編集できる人ならハッシュも書き換えられるため、これは改ざん耐性の証明ではありません）"}
          </span>
        )}
      </p>

      <h3>Findings</h3>
      {record.findings.length === 0 ? (
        <p className="muted">No findings recorded yet.</p>
      ) : (
        STATUS_SECTIONS.map(([status, heading]) => {
          const findings = sortBySeverity(record.findings.filter((f) => f.status === status));
          if (findings.length === 0) return null;
          return (
            <div key={status}>
              <h4>{heading}</h4>
              <ul className="findings">
                {findings.map((f) => (
                  <li key={f.finding_id} className={`severity-${f.severity}`}>
                    <span className="badge">{f.severity}</span>
                    <span className="source">{f.source === "ai" ? "AI推定" : "manual"}</span>
                    <strong>{f.title}</strong> — {f.detail}
                    <div className="finding-actions">
                      {STATUS_SECTIONS.filter(([s]) => s !== status).map(([target]) => (
                        <button
                          key={target}
                          onClick={() => reviewFinding(f.finding_id, target)}
                          disabled={reviewingId === f.finding_id}
                        >
                          {STATUS_LABELS[target]}
                        </button>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          );
        })
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
