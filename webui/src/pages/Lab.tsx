import { useEffect, useState } from "react";
import { api, LabHost } from "../api/client";

export default function Lab() {
  const [hosts, setHosts] = useState<LabHost[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listLab().then(setHosts).catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Lab Hosts</h2>
      <table>
        <thead>
          <tr>
            <th>name</th>
            <th>image</th>
            <th>status</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.name}>
              <td>{h.name}</td>
              <td>{h.image}</td>
              <td>{h.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
