import { useEffect, useState } from "react";
import { api, PolicyViolation } from "../api/client";

export default function Audit() {
  const [violations, setViolations] = useState<PolicyViolation[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listAudit().then(setViolations).catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Policy Violations</h2>
      <p className="muted">
        スコープ検証(ScopePolicy.authorize)が拒否したスキャン実行の試みです。
        コマンドは一切実行されていません。
      </p>
      {violations.length === 0 ? (
        <p className="muted">拒否された試みは記録されていません。</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>occurred_at</th>
              <th>target</th>
              <th>plugin</th>
              <th>reason</th>
            </tr>
          </thead>
          <tbody>
            {violations.map((v) => (
              <tr key={v.violation_id}>
                <td>{new Date(v.occurred_at).toLocaleString()}</td>
                <td>{v.target}</td>
                <td>{v.plugin}</td>
                <td>{v.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
