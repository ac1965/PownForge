import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

type StepEvent =
  | { type: "step_start"; index: number; total: number; plugin: string }
  | { type: "step_done"; index: number; plugin: string; run_id: string; returncode: number }
  | { type: "step_skipped"; index: number; plugin: string }
  | { type: "step_failed"; index: number; plugin: string; error: string };

type Status = "connecting" | "running" | "done" | "error";

export default function PlaybookLive() {
  const { jobId } = useParams<{ jobId: string }>();
  const [events, setEvents] = useState<StepEvent[]>([]);
  const [status, setStatus] = useState<Status>("connecting");
  const [runIds, setRunIds] = useState<string[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) return;
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${window.location.host}/api/ws/playbooks/${jobId}`);

    ws.onopen = () => setStatus("running");
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "done") {
        setStatus("done");
        setRunIds(message.run_ids);
        ws.close();
      } else if (message.type === "error") {
        setStatus("error");
        setErrorMessage(message.message);
        ws.close();
      } else {
        setEvents((prev) => [...prev, message as StepEvent]);
      }
    };
    ws.onerror = () => {
      setStatus("error");
      setErrorMessage("WebSocket接続に失敗しました");
    };

    return () => ws.close();
  }, [jobId]);

  const startedSteps = new Map(
    events.filter((e) => e.type === "step_start").map((e) => [e.index, e as Extract<StepEvent, { type: "step_start" }>]),
  );
  const total = [...startedSteps.values()][0]?.total ?? 0;

  return (
    <div>
      <h2>Playbook run {jobId}</h2>
      <p>
        status: <strong>{status}</strong>
      </p>
      {errorMessage && <p className="error">{errorMessage}</p>}

      <ol>
        {[...startedSteps.values()]
          .sort((a, b) => a.index - b.index)
          .map((start) => {
            const outcome = events.find(
              (e) => e.index === start.index && e.type !== "step_start",
            );
            return (
              <li key={start.index}>
                <code>{start.plugin}</code>{" "}
                {!outcome && "実行中..."}
                {outcome?.type === "step_done" && (
                  <>
                    完了(exit={outcome.returncode}) —{" "}
                    <Link to={`/runs/${outcome.run_id}`}>run {outcome.run_id}</Link>
                  </>
                )}
                {outcome?.type === "step_skipped" && <span className="muted">SKIPPED(条件不成立)</span>}
                {outcome?.type === "step_failed" && (
                  <span className="error">FAILED — {outcome.error}</span>
                )}
              </li>
            );
          })}
      </ol>
      {total > 0 && status === "running" && (
        <p className="muted">
          {startedSteps.size}/{total} ステップ開始済み
        </p>
      )}

      {status === "done" && (
        <div>
          <p>
            playbook終了: {runIds.length}件のrunを作成しました。
          </p>
          {runIds.length > 0 && (
            <p>
              <Link to="/walkthrough/new">Walkthroughを生成する</Link>
              (run一覧からチェックして選択してください: {runIds.join(", ")})
            </p>
          )}
        </div>
      )}
    </div>
  );
}
