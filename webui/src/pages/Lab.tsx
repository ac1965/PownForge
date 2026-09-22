import { FormEvent, useEffect, useState } from "react";
import { api, LabHost, TargetKind } from "../api/client";

const emptyForm = {
  name: "",
  image: "",
  kind: "host" as TargetKind,
  port: "",
  scheme: "http",
  allowedPlugins: "",
  autoRegister: true,
};

export default function Lab() {
  const [hosts, setHosts] = useState<LabHost[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [submitting, setSubmitting] = useState(false);

  const load = () => api.listLab().then(setHosts).catch((e) => setError(String(e)));

  useEffect(() => {
    load();
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setNotice(null);
    api
      .addLabHost({
        name: form.name,
        image: form.image,
        env: {},
        kind: form.kind,
        port: form.kind === "url" ? Number(form.port) || null : null,
        scheme: form.scheme,
        allowed_plugins: form.allowedPlugins
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
        auto_register: form.autoRegister,
      })
      .then((created) => {
        setForm(emptyForm);
        if (created.registration_warning) {
          setNotice(`ホストは起動しましたが、対象登録には失敗しました: ${created.registration_warning}`);
        } else if (created.target) {
          setNotice(`ホストを起動し、対象 '${created.target.name}' として登録しました。`);
        } else {
          setNotice("ホストを起動しました（対象登録はスキップされました）。");
        }
        return load();
      })
      .catch((e) => setError(String(e)))
      .finally(() => setSubmitting(false));
  };

  const remove = (name: string) => {
    const purge = confirm(`ラボホスト '${name}' を削除します。登録済みの対象も一緒に削除しますか？`);
    api
      .removeLabHost(name, purge)
      .then(load)
      .catch((e) => setError(String(e)));
  };

  return (
    <div>
      <h2>Lab Hosts</h2>
      {error && <p className="error">{error}</p>}
      {notice && <p className="muted">{notice}</p>}
      <table>
        <thead>
          <tr>
            <th>name</th>
            <th>image</th>
            <th>status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.name}>
              <td>{h.name}</td>
              <td>{h.image}</td>
              <td>{h.status}</td>
              <td>
                <button onClick={() => remove(h.name)}>削除</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>攻撃対象ホストを起動</h3>
      <p className="muted">
        隔離Dockerネットワーク(既定 <code>pownforge-lab</code>、<code>--internal</code>)上にコンテナを起動します。
      </p>
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
          image
          <input
            required
            placeholder="bkimminich/juice-shop"
            value={form.image}
            onChange={(e) => setForm({ ...form, image: e.target.value })}
          />
        </label>
        <label>
          kind
          <select
            value={form.kind}
            onChange={(e) => setForm({ ...form, kind: e.target.value as TargetKind })}
          >
            <option value="host">host (networkプラグイン向け)</option>
            <option value="url">url (web/apiプラグイン向け)</option>
          </select>
        </label>
        {form.kind === "url" && (
          <>
            <label>
              port
              <input
                required
                type="number"
                value={form.port}
                onChange={(e) => setForm({ ...form, port: e.target.value })}
              />
            </label>
            <label>
              scheme
              <select
                value={form.scheme}
                onChange={(e) => setForm({ ...form, scheme: e.target.value })}
              >
                <option value="http">http</option>
                <option value="https">https</option>
              </select>
            </label>
          </>
        )}
        <label>
          allowed plugins (comma区切り、空=all)
          <input
            placeholder="network,web"
            value={form.allowedPlugins}
            onChange={(e) => setForm({ ...form, allowedPlugins: e.target.value })}
          />
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={form.autoRegister}
            onChange={(e) => setForm({ ...form, autoRegister: e.target.checked })}
          />
          対象としてスコープに自動登録する
        </label>
        <button type="submit" disabled={submitting}>
          {submitting ? "起動中..." : "起動"}
        </button>
      </form>
    </div>
  );
}
