import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

type Status = "connecting" | "running" | "done" | "error";

export default function ScanLive() {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [lines, setLines] = useState<string[]>([]);
  const [status, setStatus] = useState<Status>("connecting");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!jobId) return;
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${window.location.host}/api/ws/scans/${jobId}`);

    ws.onopen = () => setStatus("running");
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "line") {
        setLines((prev) => [...prev, message.data]);
      } else if (message.type === "done") {
        setStatus("done");
        ws.close();
        navigate(`/runs/${message.run_id}`);
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
  }, [jobId, navigate]);

  useEffect(() => {
    preRef.current?.scrollTo({ top: preRef.current.scrollHeight });
  }, [lines]);

  return (
    <div>
      <h2>Scan {jobId}</h2>
      <p>
        status: <strong>{status}</strong>
      </p>
      {errorMessage && (
        <div>
          <p className="error">{errorMessage}</p>
          <Link to="/scan/new">別のスキャンを試す</Link>
        </div>
      )}
      <pre ref={preRef} className="live-output">
        {lines.length === 0 ? "接続中..." : lines.join("\n")}
      </pre>
    </div>
  );
}
