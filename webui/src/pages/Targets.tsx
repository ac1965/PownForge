import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Target, TargetKind } from "../api/client";

const emptyForm = {
  name: "",
  kind: "host" as TargetKind,
  address: "",
  allowedPlugins: "",
  notes: "",
};

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [submitting, setSubmitting] = useState(false);

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
        allowed_plugins: form.allowedPlugins
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
        notes: form.notes || null,
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
            <th>allowed plugins</th>
            <th>notes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {targets.map((t) => (
            <tr key={t.name}>
              <td>{t.name}</td>
              <td>{t.kind}</td>
              <td>{t.address}</td>
              <td>{t.allowed_plugins.join(", ") || "any"}</td>
              <td>{t.notes ?? ""}</td>
              <td>
                <Link to={`/scan/new?target=${encodeURIComponent(t.name)}`}>Scan</Link>{" "}
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
          </select>
        </label>
        <label>
          address
          <input
            required
            placeholder={form.kind === "url" ? "http://127.0.0.1:3000" : "127.0.0.1"}
            value={form.address}
            onChange={(e) => setForm({ ...form, address: e.target.value })}
          />
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
          notes
          <input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
        </label>
        <button type="submit" disabled={submitting}>
          {submitting ? "追加中..." : "追加"}
        </button>
      </form>
    </div>
  );
}
