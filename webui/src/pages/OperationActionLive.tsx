import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

type Status = "connecting" | "running" | "done" | "error";

export default function OperationActionLive() {
  const { name, actionId, jobId } = useParams<{ name: string; actionId: string; jobId: string }>();
  const [lines, setLines] = useState<string[]>([]);
  const [status, setStatus] = useState<Status>("connecting");
  const [runId, setRunId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!jobId) return;
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${window.location.host}/api/ws/operations/jobs/${jobId}`);

    ws.onopen = () => setStatus("running");
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "line") {
        setLines((prev) => [...prev, message.data]);
      } else if (message.type === "done") {
        setStatus("done");
        setRunId(message.run_id);
        ws.close();
      } else if (message.type === "error") {
        setStatus("error");
        setErrorMessage(message.message);
        ws.close();
      }
    };
    ws.onerror = () => {
      setStatus("error");
      setErrorMessage("WebSocket接続に失敗しました");
    };

    return () => ws.close();
  }, [jobId]);

  useEffect(() => {
    preRef.current?.scrollTo({ top: preRef.current.scrollHeight });
  }, [lines]);

  return (
    <div>
      <h2>
        Operation {name} / action {actionId}
      </h2>
      <p>
        status: <strong>{status}</strong>
      </p>
      {errorMessage && (
        <div>
          <p className="error">{errorMessage}</p>
          <Link to="/operations">Operation一覧に戻る</Link>
        </div>
      )}
      <pre ref={preRef} className="live-output">
        {lines.length === 0 ? "接続中..." : lines.join("\n")}
      </pre>
      {status === "done" && (
        <p>
          完了しました。 <Link to="/operations">Operation一覧に戻る</Link>
          {runId && (
            <>
              {" "}
              / <Link to={`/runs/${runId}`}>run {runId}</Link>
            </>
          )}
        </p>
      )}
    </div>
  );
}
