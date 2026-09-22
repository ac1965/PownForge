import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, Playbook, Target } from "../api/client";

export default function Playbooks() {
  const navigate = useNavigate();
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.listPlaybooks(), api.listTargets()])
      .then(([p, t]) => {
        setPlaybooks(p);
        setTargets(t);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const run = (name: string) => {
    const target = selectedTarget[name];
    if (!target) return;
    setRunning(name);
    setError(null);
    api
      .runPlaybook(name, target)
      .then((created) => navigate(`/playbooks/runs/${created.job_id}/live`))
      .catch((e) => setError(String(e)))
      .finally(() => setRunning(null));
  };

  return (
    <div>
      <h2>Playbooks</h2>
      <p className="muted">
        登録済みの対象に対して、複数プラグインをあらかじめ決めた順番(条件付きの場合あり)で連続実行します。
        実行順・条件は人間が事前に書いた <code>config/playbooks/*.yaml</code> で決まり、実行中にAIが次の一手を選ぶことはありません。
      </p>
      {error && <p className="error">{error}</p>}
      {playbooks.length === 0 && (
        <p className="muted">
          利用可能なPlaybookがありません。<code>config/playbooks/*.yaml</code> を追加してください。
        </p>
      )}

      {playbooks.map((playbook) => (
        <div key={playbook.name} className="card">
          <h3>{playbook.name}</h3>
          <p className="muted">{playbook.description}</p>
          <ol>
            {playbook.steps.map((step, i) => (
              <li key={i}>
                <code>{step.plugin}</code>
                {Object.keys(step.options).length > 0 && (
                  <span className="muted">
                    {" "}
                    ({Object.entries(step.options).map(([k, v]) => `${k}=${v}`).join(", ")})
                  </span>
                )}
                {step.when && (
                  <span className="muted">
                    {" "}
                    [when: step {step.when.after_step} has finding &gt;= {step.when.min_severity}]
                  </span>
                )}
              </li>
            ))}
          </ol>
          <div className="option-row">
            <select
              value={selectedTarget[playbook.name] ?? ""}
              onChange={(e) =>
                setSelectedTarget((prev) => ({ ...prev, [playbook.name]: e.target.value }))
              }
            >
              <option value="" disabled>
                対象を選択
              </option>
              {targets.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.name} ({t.address})
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={!selectedTarget[playbook.name] || running === playbook.name}
              onClick={() => run(playbook.name)}
            >
              {running === playbook.name ? "開始中..." : "実行"}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
