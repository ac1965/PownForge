import { useEffect, useState } from "react";
import { api, Target } from "../api/client";

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listTargets().then(setTargets).catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Targets</h2>
      <table>
        <thead>
          <tr>
            <th>name</th>
            <th>kind</th>
            <th>address</th>
            <th>allowed plugins</th>
            <th>notes</th>
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
