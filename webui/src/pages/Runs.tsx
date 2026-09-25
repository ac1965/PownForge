import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ChainVerification, RunRecord } from "../api/client";

export default function Runs() {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [chainResult, setChainResult] = useState<ChainVerification | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);

  useEffect(() => {
    api.listRuns().then(setRuns).catch((e) => setError(String(e)));
  }, []);

  const verifyChain = () => {
    setVerifyingChain(true);
    setChainResult(null);
    api
      .verifyRunsChain()
      .then(setChainResult)
      .catch((e) => setError(String(e)))
      .finally(() => setVerifyingChain(false));
  };

  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Runs</h2>
      <p className="muted">
        <button type="button" onClick={verifyChain} disabled={verifyingChain}>
          {verifyingChain ? "検証中..." : "証跡チェーンを検証"}
        </button>{" "}
        保存された全runの改ざん検知(ハッシュチェーン)を確認します。単発の
        stdout/stderrハッシュ検証(run detailページ)より広く、ファイル単体の
        改変も検出できます。
      </p>
      {chainResult && (
        <p className={chainResult.ok ? "verify-ok" : "verify-mismatch"}>
          {chainResult.entries_checked === 0
            ? "チェーンにエントリがまだありません(runが記録されていません)。"
            : chainResult.ok
              ? `OK: ${chainResult.entries_checked}件のチェーンエントリすべて検証済み`
              : `MISMATCH: ${chainResult.mismatches.length}件の不整合(${chainResult.mismatches
                  .map((m) => `${m.kind}/${m.run_id ?? "-"}`)
                  .join(", ")})`}
        </p>
      )}
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
