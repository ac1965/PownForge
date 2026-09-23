import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, KindClusterInfo, LabHost, LabScenario, TargetKind } from "../api/client";

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

      <KindClusterSection />
      <VulhubProviderSection />
    </div>
  );
}

function KindClusterSection() {
  const [clusters, setClusters] = useState<KindClusterInfo[]>([]);
  const [name, setName] = useState("");
  const [registerTarget, setRegisterTarget] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => api.listKindClusters().then(setClusters).catch((e) => setError(String(e)));
  useEffect(() => {
    load();
  }, []);

  const create = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    api
      .createKindCluster(name, registerTarget)
      .then((created) => {
        setName("");
        if (created.registration_warning) {
          setNotice(`クラスタ作成、対象登録は失敗: ${created.registration_warning}`);
        } else if (created.registered_target) {
          setNotice(`クラスタ '${created.cluster.name}' を作成し、対象 '${created.registered_target.name}' として登録しました。`);
        } else {
          setNotice(`クラスタ '${created.cluster.name}' を作成しました（対象登録なし）。`);
        }
        return load();
      })
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(false));
  };

  const remove = (clusterName: string) => {
    const purge = confirm(`kindクラスタ '${clusterName}' を削除します。登録済みの対象も削除しますか？`);
    setError(null);
    setNotice(null);
    api
      .deleteKindCluster(clusterName, purge)
      .then(() => {
        setNotice(`クラスタ '${clusterName}' を削除しました。`);
        return load();
      })
      .catch((e) => setError(String(e)));
  };

  return (
    <div className="card">
      <h3>kind クラスタ(Kubernetes ラボ)</h3>
      <p className="muted">
        kindクラスタを作成し、内部向けkubeconfigを <code>config/&lt;name&gt;.kubeconfig</code> に書き出して、
        <code>kind-&lt;name&gt;</code> をkubernetes対象として登録します。
      </p>
      {error && <p className="error">{error}</p>}
      {notice && <p className="muted">{notice}</p>}
      {clusters.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>name</th>
              <th>context</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {clusters.map((c) => (
              <tr key={c.name}>
                <td>{c.name}</td>
                <td>
                  <code>{c.context}</code>
                </td>
                <td>
                  <button type="button" onClick={() => remove(c.name)}>
                    削除
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form onSubmit={create} className="form-grid">
        <label>
          name
          <input required value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={registerTarget}
            onChange={(e) => setRegisterTarget(e.target.checked)}
          />
          kubernetes対象としてスコープに登録する
        </label>
        <button type="submit" disabled={busy || !name}>
          {busy ? "作成中..." : "クラスタ作成"}
        </button>
      </form>
    </div>
  );
}

function VulhubProviderSection() {
  const [scenarios, setScenarios] = useState<LabScenario[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [registerTarget, setRegisterTarget] = useState(true);

  const refresh = () =>
    api
      .listVulhubScenarios()
      .then(setScenarios)
      .catch((e) => {
        setScenarios([]);
        setError(String(e));
      });

  const filtered = useMemo(() => {
    if (!scenarios) return [];
    const q = filter.trim().toLowerCase();
    const matches = q ? scenarios.filter((s) => s.id.toLowerCase().includes(q)) : scenarios;
    return matches.slice(0, 100);
  }, [scenarios, filter]);

  const act = (label: string, scenario: string, fn: () => Promise<unknown>) => {
    setBusy(scenario);
    setError(null);
    setNotice(null);
    fn()
      .then((result) => {
        const r = result as { warning?: string; registered_target?: { name: string } | null };
        if (r && r.registered_target) {
          setNotice(`${scenario}: ${label}。対象 '${r.registered_target.name}' として登録しました。`);
        } else if (r && r.warning) {
          setNotice(`${scenario}: ${label}。${r.warning}`);
        } else {
          setNotice(`${scenario}: ${label}。`);
        }
        return refresh();
      })
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(null));
  };

  return (
    <div className="card">
      <h3>Vulhub シナリオ(外部Lab Provider)</h3>
      <p className="muted">
        意図的に脆弱な環境を起動します。compose fileがポートを全インターフェースに公開することがあるため、
        隔離されたラボホストでのみ使用してください。PownForge自身はこれらにexploitを実行しません(ライフサイクル管理のみ)。
      </p>
      {error && <p className="error">{error}</p>}
      {notice && <p className="muted">{notice}</p>}
      {scenarios === null ? (
        <button type="button" onClick={refresh}>
          シナリオを読み込む
        </button>
      ) : (
        <>
          <div className="option-row">
            <input
              placeholder="フィルタ(例: log4j, CVE-2021)"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={registerTarget}
                onChange={(e) => setRegisterTarget(e.target.checked)}
              />
              起動時にurl対象として登録
            </label>
            <button type="button" onClick={refresh}>
              再読み込み
            </button>
          </div>
          {scenarios.length === 0 ? (
            <p className="muted">
              シナリオが見つかりません。Vulhubをクローンし、<code>--vulhub-dir</code> または{" "}
              <code>POWNFORGE_VULHUB_DIR</code> を設定して <code>pownforge web serve</code> を起動してください。
            </p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>scenario</th>
                  <th>status</th>
                  <th>ports</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <code>{s.id}</code>
                    </td>
                    <td>{s.running ? "running" : "-"}</td>
                    <td>
                      {s.published_ports.map((p) => `${p.host_port}→${p.container_port}`).join(", ")}
                    </td>
                    <td>
                      <button
                        type="button"
                        disabled={busy === s.id}
                        onClick={() => act("起動", s.id, () => api.startVulhub(s.id, registerTarget))}
                      >
                        起動
                      </button>{" "}
                      <button
                        type="button"
                        disabled={busy === s.id}
                        onClick={() => act("停止", s.id, () => api.stopVulhub(s.id))}
                      >
                        停止
                      </button>{" "}
                      <button
                        type="button"
                        disabled={busy === s.id}
                        onClick={() => {
                          const purge = confirm(
                            `${s.id} を破棄します(ボリュームごと)。登録済みの対象も削除しますか？`,
                          );
                          act("破棄", s.id, () => api.cleanupVulhub(s.id, purge));
                        }}
                      >
                        破棄
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {scenarios.length > filtered.length && (
            <p className="muted">
              {scenarios.length} 件中 {filtered.length} 件を表示(フィルタで絞り込めます)。
            </p>
          )}
        </>
      )}
    </div>
  );
}
