import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  api,
  PrimitiveInfo,
  PrimitiveRunRecord,
  Target,
  ValidationLevel,
} from "../api/client";

interface OptionRow {
  key: string;
  value: string;
}

const STATUS_SYMBOL: Record<string, string> = { met: "✓", unmet: "✗", unknown: "?" };

export default function Primitives() {
  const [primitives, setPrimitives] = useState<PrimitiveInfo[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [runs, setRuns] = useState<PrimitiveRunRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [primitiveId, setPrimitiveId] = useState("");
  const [targetName, setTargetName] = useState("");
  const [level, setLevel] = useState<ValidationLevel>("validation");
  const [options, setOptions] = useState<OptionRow[]>([{ key: "", value: "" }]);
  const [running, setRunning] = useState(false);

  const [selected, setSelected] = useState<PrimitiveRunRecord | null>(null);

  const refreshRuns = () =>
    api.listPrimitiveRuns().then(setRuns).catch((e) => setError(String(e)));

  useEffect(() => {
    api.listPrimitives().then(setPrimitives).catch((e) => setError(String(e)));
    api.listTargets().then(setTargets).catch((e) => setError(String(e)));
    refreshRuns();
  }, []);

  const selectedPrimitive = useMemo(
    () => primitives.find((p) => p.descriptor.id === primitiveId),
    [primitives, primitiveId],
  );

  const run = (e: FormEvent) => {
    e.preventDefault();
    if (!primitiveId || !targetName) return;
    setRunning(true);
    setError(null);
    const optionMap = Object.fromEntries(
      options.filter((o) => o.key.trim()).map((o) => [o.key.trim(), o.value]),
    );
    api
      .runPrimitive({ primitive: primitiveId, target: targetName, level, options: optionMap })
      .then((record) => {
        setSelected(record);
        return refreshRuns();
      })
      .catch((e) => setError(String(e)))
      .finally(() => setRunning(false));
  };

  const updateOption = (i: number, field: "key" | "value", value: string) =>
    setOptions((prev) => prev.map((row, idx) => (idx === i ? { ...row, [field]: value } : row)));

  return (
    <div>
      <h2>Validation Primitives</h2>
      <p className="muted">
        許可されたラボ内で「制御された検証」を行い、前提条件・観測・証跡・クリーンアップまでを記録します。
        PownForge自身はexploitを実行しません。executionは専用ラボ(SafetyPolicyでexecution_enabled)のみ到達可能です。
      </p>
      {error && <p className="error">{error}</p>}

      <div className="card">
        <h3>実行</h3>
        <form onSubmit={run} className="form-grid">
          <label>
            primitive
            <select required value={primitiveId} onChange={(e) => setPrimitiveId(e.target.value)}>
              <option value="" disabled>
                選択してください
              </option>
              {primitives.map((p) => (
                <option key={p.descriptor.id} value={p.descriptor.id}>
                  {p.descriptor.id}（max_level={p.descriptor.max_level}）
                </option>
              ))}
            </select>
          </label>
          <label>
            target
            <select required value={targetName} onChange={(e) => setTargetName(e.target.value)}>
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
            level
            <select value={level} onChange={(e) => setLevel(e.target.value as ValidationLevel)}>
              <option value="detection">detection</option>
              <option value="validation">validation</option>
              <option value="execution">execution（専用ラボのみ）</option>
            </select>
          </label>

          {selectedPrimitive && (
            <div>
              <p className="muted">options</p>
              <ul className="muted">
                {selectedPrimitive.options.map((o) => (
                  <li key={o.name}>
                    <code>{o.name}</code>
                    {o.required ? "（必須）" : ""}: {o.description}
                  </li>
                ))}
              </ul>
              {options.map((row, i) => (
                <div key={i} className="option-row">
                  <input
                    placeholder="key（例: path）"
                    value={row.key}
                    onChange={(e) => updateOption(i, "key", e.target.value)}
                  />
                  <input
                    placeholder="value"
                    value={row.value}
                    onChange={(e) => updateOption(i, "value", e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => setOptions((prev) => prev.filter((_, idx) => idx !== i))}
                  >
                    削除
                  </button>
                </div>
              ))}
              <button type="button" onClick={() => setOptions((prev) => [...prev, { key: "", value: "" }])}>
                + option行を追加
              </button>
            </div>
          )}

          <button type="submit" disabled={running || !primitiveId || !targetName}>
            {running ? "実行中..." : "実行"}
          </button>
        </form>
      </div>

      <div className="card">
        <h3>実行履歴</h3>
        {runs.length === 0 ? (
          <p className="muted">まだプリミティブ実行がありません。</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th>
                <th>run_id</th>
                <th>primitive</th>
                <th>target</th>
                <th>level</th>
                <th>created</th>
                <th>report</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.run_id}>
                  <td>
                    <button type="button" onClick={() => setSelected(r)}>
                      表示
                    </button>
                  </td>
                  <td>
                    <code>{r.run_id}</code>
                    {r.residual_resources.length > 0 && <span className="error"> ⚠残留</span>}
                  </td>
                  <td>{r.primitive}</td>
                  <td>{r.target}</td>
                  <td>{r.level_reached}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                  <td>
                    <a href={api.primitiveRunReportPdfUrl(r.run_id)} target="_blank" rel="noreferrer">
                      PDF
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selected && <PrimitiveRunDetail record={selected} />}
    </div>
  );
}

function PrimitiveRunDetail({ record }: { record: PrimitiveRunRecord }) {
  const evidence = record.evidence;
  return (
    <div className="card">
      <h3>
        Primitive run <code>{record.run_id}</code>
      </h3>
      <p>
        {record.primitive} → {record.target}（requested={record.requested_level}, reached=
        {record.level_reached}）
      </p>
      {record.notes && <p className="muted">note: {record.notes}</p>}
      <p>
        <a href={api.primitiveRunReportPdfUrl(record.run_id)} target="_blank" rel="noreferrer">
          PDFレポートをダウンロード
        </a>
      </p>

      <h4>前提条件</h4>
      <ul>
        {record.preconditions.preconditions.map((p) => (
          <li key={p.id}>
            {STATUS_SYMBOL[p.status] ?? "?"} <strong>{p.status}</strong> <code>{p.id}</code>:{" "}
            {p.description}
            {p.detail ? ` — ${p.detail}` : ""}
          </li>
        ))}
      </ul>

      <h4>観測（事実）</h4>
      {evidence && evidence.observations.length > 0 ? (
        <ul>
          {evidence.observations.map((o) => (
            <li key={o.id}>
              <code>{o.type}</code> ({o.provenance.kind}): {o.detail}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">観測はありません。</p>
      )}

      <h4>Findings / Claims</h4>
      {evidence && evidence.findings.length > 0 ? (
        <ul>
          {evidence.findings.map((f) => (
            <li key={f.finding_id}>
              <span className={`badge severity-${f.severity}`}>{f.severity}</span> {f.title} — {f.detail}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">Findingはありません。</p>
      )}
      {evidence && evidence.claims.length > 0 && (
        <ul>
          {evidence.claims.map((c) => (
            <li key={c.id}>
              <strong>[{c.confidence}]</strong> {c.statement}
            </li>
          ))}
        </ul>
      )}

      <h4>生成リソースとクリーンアップ</h4>
      {record.resources.length > 0 ? (
        <ul>
          {record.resources.map((r) => (
            <li key={r.id}>
              <code>{r.status}</code> {r.type}: {r.description}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">生成されたリソースはありません。</p>
      )}
      {record.residual_resources.length > 0 && (
        <p className="error">
          ⚠ {record.residual_resources.length} 件のリソースがクリーンアップ未検証のまま残っています。
        </p>
      )}
    </div>
  );
}
