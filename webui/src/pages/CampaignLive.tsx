import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

type StepEvent =
  | {
      type: "step_start";
      target_index: number;
      target_total: number;
      target: string;
      step_index: number;
      step_total: number;
      plugin: string;
    }
  | { type: "step_done"; target: string; plugin: string; run_id: string; returncode: number }
  | { type: "step_skipped"; target: string; plugin: string }
  | { type: "step_failed"; target: string; plugin: string; error: string }
  | { type: "target_failed"; target: string; error: string };

type Status = "connecting" | "running" | "done" | "error";

export default function CampaignLive() {
  const { jobId } = useParams<{ jobId: string }>();
  const [events, setEvents] = useState<StepEvent[]>([]);
  const [status, setStatus] = useState<Status>("connecting");
  const [sessionName, setSessionName] = useState<string | null>(null);
  const [stageCount, setStageCount] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) return;
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${window.location.host}/api/ws/campaigns/${jobId}`);

    ws.onopen = () => setStatus("running");
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "done") {
        setStatus("done");
        setSessionName(message.session_name);
        setStageCount(message.stage_count);
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

  const targets = [...new Set(events.map((e) => e.target))];
  const startEvents = events.filter((e): e is Extract<StepEvent, { type: "step_start" }> => e.type === "step_start");
  const targetTotal = startEvents[0]?.target_total ?? 0;

  return (
    <div>
      <h2>Campaign run {jobId}</h2>
      <p>
        status: <strong>{status}</strong>
      </p>
      {errorMessage && <p className="error">{errorMessage}</p>}

      {targets.map((target) => {
        const targetFailed = events.find((e) => e.type === "target_failed" && e.target === target) as
          | Extract<StepEvent, { type: "target_failed" }>
          | undefined;
        const steps = startEvents.filter((e) => e.target === target);
        return (
          <div key={target} className="card">
            <h3>{target}</h3>
            {targetFailed && <p className="error">FAILED — {targetFailed.error}</p>}
            <ol>
              {steps.map((start) => {
                const outcome = events.find(
                  (e) => e.type !== "step_start" && "plugin" in e && e.target === target && e.plugin === start.plugin,
                ) as Exclude<StepEvent, { type: "step_start" } | { type: "target_failed" }> | undefined;
                return (
                  <li key={start.plugin}>
                    <code>{start.plugin}</code>{" "}
                    {!outcome && "実行中..."}
                    {outcome?.type === "step_done" && (
                      <>
                        完了(exit={outcome.returncode}) — <Link to={`/runs/${outcome.run_id}`}>run {outcome.run_id}</Link>
                      </>
                    )}
                    {outcome?.type === "step_skipped" && <span className="muted">SKIPPED(条件不成立)</span>}
                    {outcome?.type === "step_failed" && <span className="error">FAILED — {outcome.error}</span>}
                  </li>
                );
              })}
            </ol>
          </div>
        );
      })}

      {targetTotal > 0 && status === "running" && (
        <p className="muted">
          {targets.length}/{targetTotal} target開始済み
        </p>
      )}

      {status === "done" && (
        <div>
          <p>
            campaign終了: Attack Session <code>{sessionName}</code> を {stageCount}件のstageで作成しました。
          </p>
          <Link to="/attack-sessions">Attack Session一覧を見る</Link>
        </div>
      )}
    </div>
  );
}
