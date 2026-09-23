import { useEffect, useState } from "react";
import { api, CveExposure, Target } from "../api/client";

type ScopeKind = "all" | "target" | "engagement";

export default function Engagement() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scopeKind, setScopeKind] = useState<ScopeKind>("all");
  const [targetName, setTargetName] = useState("");
  const [engagementName, setEngagementName] = useState("");
  const [format, setFormat] = useState<"markdown" | "html">("markdown");
  const [report, setReport] = useState<{ markdown?: string; html?: string } | null>(null);
  const [cveMatrix, setCveMatrix] = useState<CveExposure[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listTargets().then(setTargets).catch((e) => setError(String(e)));
  }, []);

  const scope = () => {
    if (scopeKind === "target") return { target: targetName };
    if (scopeKind === "engagement") return { engagement: engagementName };
    return {};
  };

  const scopeReady =
    scopeKind === "all" ||
    (scopeKind === "target" && targetName) ||
    (scopeKind === "engagement" && engagementName.trim());

  const generate = () => {
    setLoading(true);
    setError(null);
    setReport(null);
    setCveMatrix(null);
    const s = scope();
    Promise.all([api.getEngagementReport(s, format), api.getEngagementCveMatrix(s)])
      .then(([rep, json]) => {
        setReport(rep);
        setCveMatrix(json.cve_exposure);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  return (
    <div>
      <h2>Engagement Report</h2>
      <p className="muted">
        スキャン/手動run(RunRecord)と検証プリミティブrun(PrimitiveRunRecord)を横断した1つの
        エンゲージメント像を生成します(読み取り専用)。
      </p>
      {error && <p className="error">{error}</p>}

      <div className="card">
        <div className="form-grid">
          <label>
            scope
            <select value={scopeKind} onChange={(e) => setScopeKind(e.target.value as ScopeKind)}>
              <option value="all">all(全run)</option>
              <option value="target">target(1対象)</option>
              <option value="engagement">engagement(メンバー横断)</option>
            </select>
          </label>
          {scopeKind === "target" && (
            <label>
              target
              <select value={targetName} onChange={(e) => setTargetName(e.target.value)}>
                <option value="" disabled>
                  選択してください
                </option>
                {targets.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          {scopeKind === "engagement" && (
            <label>
              engagement 名
              <input value={engagementName} onChange={(e) => setEngagementName(e.target.value)} />
            </label>
          )}
          <label>
            format
            <select value={format} onChange={(e) => setFormat(e.target.value as "markdown" | "html")}>
              <option value="markdown">markdown</option>
              <option value="html">html</option>
            </select>
          </label>
          <div className="option-row">
            <button type="button" onClick={generate} disabled={loading || !scopeReady}>
              {loading ? "生成中..." : "生成"}
            </button>
            <a href={api.engagementReportPdfUrl(scope())} target="_blank" rel="noreferrer">
              PDFをダウンロード
            </a>
          </div>
        </div>
      </div>

      {cveMatrix && cveMatrix.length > 0 && (
        <div className="card">
          <h3>CVE露出マトリクス</h3>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>検出(scan)</th>
                <th>検証(primitive)</th>
                <th>最高到達</th>
                <th>手動exploit証跡</th>
              </tr>
            </thead>
            <tbody>
              {cveMatrix.map((e) => (
                <tr key={e.cve}>
                  <td>{e.cve}</td>
                  <td>{e.scan_plugins.join(", ") || "-"}</td>
                  <td>
                    {e.primitive_ids.join(", ") || "-"}
                    {e.confirmed_validation ? " (確認済)" : ""}
                  </td>
                  <td>{e.highest_validation ?? "-"}</td>
                  <td>
                    {e.manual_run_ids.length > 0
                      ? `あり: ${e.manual_run_ids.length}件 (証跡${e.manual_artifact_count})`
                      : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {report?.markdown && (
        <div className="card">
          <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{report.markdown}</pre>
        </div>
      )}
      {report?.html && (
        <div className="card">
          <iframe
            title="engagement-report"
            srcDoc={report.html}
            style={{ width: "100%", height: "70vh", border: "1px solid #ddd" }}
          />
        </div>
      )}
    </div>
  );
}
