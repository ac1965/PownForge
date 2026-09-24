import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Target, TargetEnvironment, TargetKind, TargetType } from "../api/client";

const emptyForm = {
  name: "",
  kind: "host" as TargetKind,
  address: "",
  type: "" as TargetType | "",
  environment: "local-lab" as TargetEnvironment,
  allowedPlugins: "",
  notes: "",
  maxConcurrent: "",
};

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [submitting, setSubmitting] = useState(false);
  const [excludeReason, setExcludeReason] = useState<Record<string, string>>({});

  const load = () => api.listTargets().then(setTargets).catch((e) => setError(String(e)));

  useEffect(() => {
    load();
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    api
      .addTarget({
        name: form.name,
        kind: form.kind,
        address: form.address,
        type: form.type || null,
        environment: form.environment,
        allowed_plugins: form.allowedPlugins
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
        notes: form.notes || null,
        excluded: false,
        exclusion_reason: null,
        max_concurrent: form.maxConcurrent ? Number(form.maxConcurrent) : null,
      })
      .then(() => {
        setForm(emptyForm);
        return load();
      })
      .catch((e) => setError(String(e)))
      .finally(() => setSubmitting(false));
  };

  const remove = (name: string) => {
    if (!confirm(`target '${name}' を削除しますか？`)) return;
    api
      .removeTarget(name)
      .then(load)
      .catch((e) => setError(String(e)));
  };

  const exclude = (name: string) => {
    api
      .excludeTarget(name, excludeReason[name] ?? "")
      .then(load)
      .catch((e) => setError(String(e)));
  };

  const include = (name: string) => {
    api
      .includeTarget(name)
      .then(load)
      .catch((e) => setError(String(e)));
  };

  return (
    <div>
      <h2>Targets</h2>
      {error && <p className="error">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>name</th>
            <th>kind</th>
            <th>address</th>
            <th>type</th>
            <th>environment</th>
            <th>allowed plugins</th>
            <th>max concurrent</th>
            <th>notes</th>
            <th>status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {targets.map((t) => (
            <tr key={t.name}>
              <td>{t.name}</td>
              <td>{t.kind}</td>
              <td>{t.address}</td>
              <td>{t.type ?? "-"}</td>
              <td>{t.environment}</td>
              <td>{t.allowed_plugins.join(", ") || "any"}</td>
              <td>{t.max_concurrent ?? "unlimited"}</td>
              <td>{t.notes ?? ""}</td>
              <td>
                {t.excluded ? (
                  <span className="error">
                    EXCLUDED{t.exclusion_reason ? `: ${t.exclusion_reason}` : ""}
                  </span>
                ) : (
                  <span className="muted">active</span>
                )}
              </td>
              <td>
                <Link to={`/scan/new?target=${encodeURIComponent(t.name)}`}>Scan</Link>{" "}
                {t.excluded ? (
                  <button onClick={() => include(t.name)}>含める</button>
                ) : (
                  <span className="option-row">
                    <input
                      type="text"
                      placeholder="除外理由(任意)"
                      value={excludeReason[t.name] ?? ""}
                      onChange={(e) =>
                        setExcludeReason((prev) => ({ ...prev, [t.name]: e.target.value }))
                      }
                    />
                    <button onClick={() => exclude(t.name)}>除外</button>
                  </span>
                )}{" "}
                <button onClick={() => remove(t.name)}>削除</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>対象を追加</h3>
      <form onSubmit={submit} className="form-grid">
        <label>
          name
          <input
            required
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
        </label>
        <label>
          kind
          <select
            value={form.kind}
            onChange={(e) => setForm({ ...form, kind: e.target.value as TargetKind })}
          >
            <option value="host">host</option>
            <option value="url">url</option>
            <option value="path">path</option>
          </select>
        </label>
        <label>
          address
          <input
            required
            placeholder={
              form.kind === "url" ? "http://127.0.0.1:3000" : form.kind === "path" ? "./src" : "127.0.0.1"
            }
            value={form.address}
            onChange={(e) => setForm({ ...form, address: e.target.value })}
          />
        </label>
        <label>
          type (任意、分類用)
          <select
            value={form.type}
            onChange={(e) => setForm({ ...form, type: e.target.value as TargetType | "" })}
          >
            <option value="">-</option>
            <option value="network">network</option>
            <option value="web">web</option>
            <option value="api">api</option>
            <option value="kubernetes">kubernetes</option>
            <option value="container">container</option>
            <option value="source-code">source-code</option>
          </select>
        </label>
        <label>
          environment
          <select
            value={form.environment}
            onChange={(e) => setForm({ ...form, environment: e.target.value as TargetEnvironment })}
          >
            <option value="local-lab">local-lab</option>
            <option value="staging">staging</option>
            <option value="production">production</option>
          </select>
        </label>
        <label>
          allowed plugins (comma区切り、空=all)
          <input
            placeholder="network,web"
            value={form.allowedPlugins}
            onChange={(e) => setForm({ ...form, allowedPlugins: e.target.value })}
          />
        </label>
        <label>
          max concurrent scans (任意、空=無制限)
          <input
            type="number"
            min={1}
            placeholder="unlimited"
            value={form.maxConcurrent}
            onChange={(e) => setForm({ ...form, maxConcurrent: e.target.value })}
          />
        </label>
        <label>
          notes{form.environment === "production" ? "（productionは必須：認可/契約の参照）" : ""}
          <input
            required={form.environment === "production"}
            value={form.notes}
            onChange={(e) => setForm({ ...form, notes: e.target.value })}
          />
        </label>
        <button type="submit" disabled={submitting}>
          {submitting ? "追加中..." : "追加"}
        </button>
      </form>
    </div>
  );
}
