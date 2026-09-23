import { FormEvent, useEffect, useRef, useState } from "react";
import { api, RunRecord, Target } from "../api/client";

const PHASES = [
  "",
  "discovery",
  "vuln-confirm",
  "exploit",
  "initial-access",
  "privilege-escalation",
  "lateral-movement",
  "persistence",
  "impact",
];

export default function ImportRun() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [target, setTarget] = useState("");
  const [command, setCommand] = useState("");
  const [output, setOutput] = useState("");
  const [tool, setTool] = useState("");
  const [phase, setPhase] = useState("");
  const [cve, setCve] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RunRecord | null>(null);

  useEffect(() => {
    api.listTargets().then(setTargets).catch((e) => setError(String(e)));
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setResult(null);
    const form = new FormData();
    form.set("target", target);
    form.set("command", command);
    form.set("output", output);
    if (tool) form.set("tool", tool);
    if (phase) form.set("phase", phase);
    cve
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean)
      .forEach((c) => form.append("cve", c));
    const files = fileRef.current?.files;
    if (files) {
      for (let i = 0; i < files.length; i++) form.append("artifacts", files[i]);
    }
    api
      .importRun(form)
      .then((rec) => {
        setResult(rec);
        setCommand("");
        setOutput("");
        setCve("");
        if (fileRef.current) fileRef.current.value = "";
      })
      .catch((e) => setError(String(e)))
      .finally(() => setSubmitting(false));
  };

  return (
    <div>
      <h2>Import 手動工程の証跡</h2>
      <p className="muted">
        別ツール(Metasploit等)で人間が実施したexploit工程の証跡を記録します。
        PownForgeは <code>command</code> を実行しません(記録のみ)。成果物(pcap/セッション記録/
        スクショ)を添付でき、CVEタグは横断レポートのCVE露出マトリクスに反映されます。
      </p>
      {error && <p className="error">{error}</p>}
      {result && (
        <p className="muted">
          run <code>{result.run_id}</code> を記録しました
          {result.artifacts.length > 0 ? `（証跡 ${result.artifacts.length} 件）` : ""}。
        </p>
      )}

      <form onSubmit={submit} className="form-grid">
        <label>
          target
          <select required value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="" disabled>
              選択してください
            </option>
            {targets.map((t) => (
              <option key={t.name} value={t.name}>
                {t.name} ({t.address})
              </option>
            ))}
          </select>
        </label>
        <label>
          command（実行された内容。PownForgeは実行しません）
          <input
            required
            placeholder="msfconsole -x 'use exploit/...; run'"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
          />
        </label>
        <label>
          output（出力/セッション記録の貼り付け）
          <textarea required rows={6} value={output} onChange={(e) => setOutput(e.target.value)} />
        </label>
        <label>
          tool（任意）
          <input placeholder="msfconsole" value={tool} onChange={(e) => setTool(e.target.value)} />
        </label>
        <label>
          phase（任意）
          <select value={phase} onChange={(e) => setPhase(e.target.value)}>
            {PHASES.map((p) => (
              <option key={p} value={p}>
                {p || "(なし)"}
              </option>
            ))}
          </select>
        </label>
        <label>
          CVE（カンマ区切り、任意）
          <input placeholder="CVE-2021-44228" value={cve} onChange={(e) => setCve(e.target.value)} />
        </label>
        <label>
          成果物ファイル（任意、複数可）
          <input type="file" multiple ref={fileRef} />
        </label>
        <button type="submit" disabled={submitting || !target || !command || !output}>
          {submitting ? "記録中..." : "証跡を記録"}
        </button>
      </form>
    </div>
  );
}
