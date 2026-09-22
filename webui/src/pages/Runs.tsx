import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, RunRecord } from "../api/client";

export default function Runs() {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listRuns().then(setRuns).catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Runs</h2>
      <table>
        <thead>
          <tr>
            <th>run_id</th>
            <th>target</th>
            <th>plugin</th>
            <th>created</th>
            <th>findings</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.run_id}>
              <td>
                <Link to={`/runs/${r.run_id}`}>{r.run_id}</Link>
              </td>
              <td>{r.target}</td>
              <td>{r.plugin}</td>
              <td>{new Date(r.created_at).toLocaleString()}</td>
              <td>{r.findings.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
