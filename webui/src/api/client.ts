export type TargetKind = "host" | "url";

export interface Target {
  name: string;
  kind: TargetKind;
  address: string;
  allowed_plugins: string[];
  notes: string | null;
}

export interface LabHost {
  name: string;
  image: string;
  status: string;
}

export interface Evidence {
  command: string[];
  started_at: string;
  finished_at: string;
  returncode: number;
  stdout_sha256: string;
  stderr_sha256: string;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "needs-review" | "confirmed" | "false-positive";

export interface Finding {
  finding_id: string;
  title: string;
  severity: Severity;
  detail: string;
  source: string;
  status: FindingStatus;
}

export interface RunRecord {
  run_id: string;
  target: string;
  plugin: string;
  created_at: string;
  evidence: Evidence;
  output: Record<string, unknown>;
  findings: Finding[];
  analysis: string | null;
}

export interface PluginInfo {
  name: string;
  version: string;
  description: string;
  required_tool: string;
  available: boolean;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}) as { detail?: string });
    throw new Error(body.detail || `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  listTargets: () => request<Target[]>("/targets"),
  addTarget: (target: Target) =>
    request<Target>("/targets", { method: "POST", body: JSON.stringify(target) }),
  removeTarget: (name: string) =>
    request<void>(`/targets/${encodeURIComponent(name)}`, { method: "DELETE" }),

  listPlugins: () => request<PluginInfo[]>("/plugins"),

  listLab: () => request<LabHost[]>("/lab"),

  listRuns: () => request<RunRecord[]>("/runs"),
  getRun: (runId: string) => request<RunRecord>(`/runs/${runId}`),
  getRunReport: (runId: string) => request<{ markdown: string }>(`/runs/${runId}/report`),
  analyzeRun: (runId: string) => request<RunRecord>(`/runs/${runId}/analyze`, { method: "POST" }),
  reviewFinding: (runId: string, findingId: string, status: FindingStatus) =>
    request<RunRecord>(`/runs/${runId}/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
};
