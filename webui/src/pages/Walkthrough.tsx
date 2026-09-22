import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, RunRecord, WalkthroughResult } from "../api/client";

export default function Walkthrough() {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [target, setTarget] = useState("");
  const [model, setModel] = useState("");
  const [format, setFormat] = useState<"markdown" | "html">("markdown");
  const [result, setResult] = useState<WalkthroughResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    api.listRuns().then(setRuns).catch((e) => setError(String(e)));
  }, []);

  const targets = useMemo(() => [...new Set(runs.map((r) => r.target))].sort(), [runs]);

  const toggleRun = (runId: string) => {
    setSelected((prev) =>
      prev.includes(runId) ? prev.filter((id) => id !== runId) : [...prev, runId],
    );
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setResult(null);
    api
      .createWalkthrough({
        run_ids: selected,
        target: selected.length === 0 ? target || null : null,
        model: model || null,
        format,
      })
      .then(setResult)
      .catch((e) => setError(String(e)))
      .finally(() => setSubmitting(false));
  };

  const downloadHtml = () => {
    if (!result?.html) return;
    const blob = new Blob([result.html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "walkthrough.html";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <h2>Walkthrough</h2>
      <p className="muted">
        複数のrunをまたぐ物語調のウォークスルーをAIに生成させます(読み取り専用: どのrunのfindings/分析も書き換えません)。
      </p>
      {error && <p className="error">{error}</p>}

      <form onSubmit={submit} className="form-grid">
        <div>
          <p>含めるrun(チェックしたものを指定順に含める。1件もチェックしなければ下のtargetの全runを時系列で使う)</p>
          <table>
            <thead>
              <tr>
                <th></th>
                <th>run_id</th>
                <th>target</th>
                <th>plugin</th>
                <th>created</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.run_id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.includes(r.run_id)}
                      onChange={() => toggleRun(r.run_id)}
                    />
                  </td>
                  <td>{r.run_id}</td>
                  <td>{r.target}</td>
                  <td>{r.plugin}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <label>
          target(runを1件もチェックしなかった場合のみ使用)
          <select value={target} onChange={(e) => setTarget(e.target.value)} disabled={selected.length > 0}>
            <option value="">選択してください</option>
            {targets.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label>
          model(任意、Ollamaモデル名)
          <input value={model} onChange={(e) => setModel(e.target.value)} placeholder="qwen3:14b" />
        </label>
        <label>
          format
          <select value={format} onChange={(e) => setFormat(e.target.value as "markdown" | "html")}>
            <option value="markdown">markdown</option>
            <option value="html">html</option>
          </select>
        </label>
        <button type="submit" disabled={submitting || (selected.length === 0 && !target)}>
          {submitting ? "生成中..." : "生成"}
        </button>
      </form>

      {result && (
        <div>
          <h3>AIの提案(要確認)</h3>
          <p className="muted">これらはAIによる提案です。実行するかどうかは人間が判断してください。</p>
          {result.suggestions.length === 0 ? (
            <p className="muted">具体的な提案はありませんでした。</p>
          ) : (
            <ul>
              {result.suggestions.map((s) => (
                <li key={s.suggestion_id}>
                  <strong>{s.title}</strong>
                  {s.plugin && <code className="badge-plugin">{s.plugin}</code>}
                  {" — "}
                  {s.rationale}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {result?.markdown && (
        <div>
          <h3>結果(Markdown)</h3>
          <pre>{result.markdown}</pre>
        </div>
      )}
      {result?.html && (
        <div>
          <h3>結果(HTML)</h3>
          <button onClick={downloadHtml}>ダウンロード</button>
          <iframe
            title="walkthrough-preview"
            srcDoc={result.html}
            sandbox=""
            style={{ width: "100%", height: "600px", border: "1px solid #ccc", marginTop: "0.5rem" }}
          />
        </div>
      )}
    </div>
  );
}
