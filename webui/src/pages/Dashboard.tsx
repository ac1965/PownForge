import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, LabHost, PolicyViolation, RunRecord, Target } from "../api/client";

export default function Dashboard() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [lab, setLab] = useState<LabHost[]>([]);
  const [violations, setViolations] = useState<PolicyViolation[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.listTargets(), api.listRuns(), api.listLab(), api.listAudit()])
      .then(([t, r, l, v]) => {
        setTargets(t);
        setRuns(r);
        setLab(l);
        setViolations(v);
      })
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="error">{error}</p>;

  return (
    <div className="panels">
      <section className="panel">
        <h2>Targets ({targets.length})</h2>
        <ul>
          {targets.map((t) => (
            <li key={t.name}>
              {t.name} — {t.address}
            </li>
          ))}
        </ul>
        <Link to="/targets">全て見る →</Link>
      </section>
      <section className="panel">
        <h2>Recent Runs</h2>
        <ul>
          {runs.slice(0, 5).map((r) => (
            <li key={r.run_id}>
              <Link to={`/runs/${r.run_id}`}>
                {r.target} / {r.plugin}
              </Link>{" "}
              <time>{new Date(r.created_at).toLocaleString()}</time>
            </li>
          ))}
        </ul>
        <Link to="/runs">全て見る →</Link>
      </section>
      <section className="panel">
        <h2>Lab Hosts ({lab.length})</h2>
        <ul>
          {lab.map((h) => (
            <li key={h.name}>
              {h.name} ({h.image}) — {h.status}
            </li>
          ))}
        </ul>
        <Link to="/lab">全て見る →</Link>
      </section>
      <section className="panel">
        <h2>Policy Violations ({violations.length})</h2>
        <ul>
          {violations.slice(0, 5).map((v) => (
            <li key={v.violation_id}>
              {v.target} / {v.plugin} — {v.reason}
            </li>
          ))}
        </ul>
        <Link to="/audit">全て見る →</Link>
      </section>
    </div>
  );
}
