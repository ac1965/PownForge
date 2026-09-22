import { FormEvent, useEffect, useState } from "react";
import { api, AttackSession, RunRecord } from "../api/client";

export default function AttackSessions() {
  const [sessions, setSessions] = useState<AttackSession[]>([]);
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<AttackSession | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newEngagement, setNewEngagement] = useState("");
  const [creating, setCreating] = useState(false);

  const [stageRunId, setStageRunId] = useState("");
  const [stageLabel, setStageLabel] = useState("");
  const [addingStage, setAddingStage] = useState(false);

  const [format, setFormat] = useState<"markdown" | "html">("markdown");
  const [report, setReport] = useState<{ markdown?: string; html?: string } | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);

  const refreshSessions = () => api.listAttackSessions().then(setSessions).catch((e) => setError(String(e)));

  useEffect(() => {
    refreshSessions();
    api.listRuns().then(setRuns).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      setReport(null);
      return;
    }
    setError(null);
    api.getAttackSession(selected).then(setDetail).catch((e) => setError(String(e)));
    setReport(null);
  }, [selected]);

  const createSession = (e: FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    api
      .createAttackSession({
        name: newName,
        description: newDescription,
        engagement: newEngagement || null,
      })
      .then((created) => {
        setNewName("");
        setNewDescription("");
        setNewEngagement("");
        return refreshSessions().then(() => setSelected(created.name));
      })
      .catch((e) => setError(String(e)))
      .finally(() => setCreating(false));
  };

  const addStage = (e: FormEvent) => {
    if (!selected) return;
    e.preventDefault();
    setAddingStage(true);
    setError(null);
    api
      .addAttackSessionStage(selected, stageRunId, stageLabel)
      .then((updated) => {
        setDetail(updated);
        setStageRunId("");
        setStageLabel("");
      })
      .catch((e) => setError(String(e)))
      .finally(() => setAddingStage(false));
  };

  const loadReport = () => {
    if (!selected) return;
    setLoadingReport(true);
    setError(null);
    api
      .getAttackSessionReport(selected, format)
      .then(setReport)
      .catch((e) => setError(String(e)))
      .finally(() => setLoadingReport(false));
  };

  return (
    <div>
      <h2>Attack Session</h2>
      <p className="muted">
        既に記録済みのrunを、名前付きの経路として並べて保存・再参照します。ここで新しいスキャンが実行されることはなく、
        既存run-idの存在確認のみを行います。
      </p>
      {error && <p className="error">{error}</p>}

      <div className="card">
        <h3>新規作成</h3>
        <form onSubmit={createSession} className="form-grid">
          <label>
            name
            <input value={newName} onChange={(e) => setNewName(e.target.value)} required />
          </label>
          <label>
            description(任意)
            <input value={newDescription} onChange={(e) => setNewDescription(e.target.value)} />
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
        {sessions.length === 0 ? (
          <p className="muted">まだAttackSessionがありません。</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th>
                <th>name</th>
                <th>description</th>
                <th>engagement</th>
                <th>stages</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.name}>
                  <td>
                    <button type="button" onClick={() => setSelected(s.name)}>
                      表示
                    </button>
                  </td>
                  <td>{s.name}</td>
                  <td>{s.description}</td>
                  <td>{s.engagement ?? "-"}</td>
                  <td>{s.stages.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <div className="card">
          <h3>{detail.name}</h3>
          <p className="muted">{detail.description}</p>
          {detail.engagement && <p className="muted">engagement: {detail.engagement}</p>}

          <ol>
            {detail.stages.map((stage, i) => (
              <li key={i}>
                <code>{stage.run_id}</code>
                {stage.label && <span> — {stage.label}</span>}
              </li>
            ))}
          </ol>
          {detail.stages.length === 0 && <p className="muted">まだstageがありません。</p>}

          <form onSubmit={addStage} className="option-row">
            <select value={stageRunId} onChange={(e) => setStageRunId(e.target.value)} required>
              <option value="" disabled>
                runを選択
              </option>
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.run_id} ({r.target}/{r.plugin})
                </option>
              ))}
            </select>
            <input
              value={stageLabel}
              onChange={(e) => setStageLabel(e.target.value)}
              placeholder="label(任意)"
            />
            <button type="submit" disabled={addingStage || !stageRunId}>
              {addingStage ? "追加中..." : "stage追加"}
            </button>
          </form>

          <div className="option-row">
            <select value={format} onChange={(e) => setFormat(e.target.value as "markdown" | "html")}>
              <option value="markdown">markdown</option>
              <option value="html">html</option>
            </select>
            <button type="button" onClick={loadReport} disabled={loadingReport || detail.stages.length === 0}>
              {loadingReport ? "生成中..." : "レポート表示"}
            </button>
          </div>

          {report?.markdown && (
            <div>
              <h4>結果(Markdown)</h4>
              <pre>{report.markdown}</pre>
            </div>
          )}
          {report?.html && (
            <div>
              <h4>結果(HTML)</h4>
              <iframe
                title="attack-session-report-preview"
                srcDoc={report.html}
                sandbox=""
                style={{ width: "100%", height: "600px", border: "1px solid #ccc", marginTop: "0.5rem" }}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
