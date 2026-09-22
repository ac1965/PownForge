export type TargetKind = "host" | "url";
export type TargetType = "network" | "web" | "api" | "kubernetes" | "container";
export type TargetEnvironment = "local-lab" | "staging" | "production";

export interface Target {
  name: string;
  kind: TargetKind;
  address: string;
  allowed_plugins: string[];
  notes: string | null;
  type: TargetType | null;
  environment: TargetEnvironment;
}

export interface LabHost {
  name: string;
  image: string;
  status: string;
}

export interface LabHostCreate {
  name: string;
  image: string;
  env: Record<string, string>;
  kind: TargetKind;
  port: number | null;
  scheme: string;
  allowed_plugins: string[];
  auto_register: boolean;
}

export interface LabHostCreated {
  host: LabHost;
  target: Target | null;
  registration_warning: string | null;
}

export interface Evidence {
  command: string[];
  started_at: string;
  finished_at: string;
  returncode: number;
  stdout_sha256: string;
  stderr_sha256: string;
  tool_version: string | null;
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
  via_target: string | null;
  engagement: string | null;
  kill_chain_phase: KillChainPhase | null;
}

export interface PluginInfo {
  name: string;
  version: string;
  description: string;
  required_tool: string;
  available: boolean;
  expected_kind: TargetKind | null;
}

export interface PolicyViolation {
  violation_id: string;
  occurred_at: string;
  target: string;
  plugin: string;
  reason: string;
}

export interface HashCheck {
  ok: boolean;
  expected: string;
  actual: string;
}

export interface EvidenceVerification {
  run_id: string;
  stdout: HashCheck;
  stderr: HashCheck;
  ok: boolean;
}

export interface ScanCreated {
  job_id: string;
  status: string;
}

export interface ScanStatus {
  job_id: string;
  status: string;
  run_id: string | null;
  error: string | null;
}

export interface PlaybookStepCondition {
  after_step: number;
  min_severity: Severity;
}

export interface PlaybookStep {
  plugin: string;
  options: Record<string, string>;
  when: PlaybookStepCondition | null;
}

export interface Playbook {
  name: string;
  description: string;
  steps: PlaybookStep[];
}

export interface PlaybookRunCreated {
  job_id: string;
  status: string;
}

export type KillChainPhase =
  | "discovery"
  | "vuln-confirm"
  | "exploit"
  | "initial-access"
  | "privilege-escalation"
  | "lateral-movement"
  | "persistence"
  | "impact";

export interface AttackSessionStage {
  run_id: string;
  label: string;
}

export interface AttackSession {
  name: string;
  description: string;
  engagement: string | null;
  stages: AttackSessionStage[];
}

export type Language = "ja" | "en";

export interface AppSettings {
  model: string | null;
  language: Language;
}

export interface WalkthroughRequest {
  run_ids: string[];
  target: string | null;
  model: string | null;
  language: Language | null;
  format: "markdown" | "html";
}

export interface Suggestion {
  suggestion_id: string;
  title: string;
  plugin: string | null;
  rationale: string;
}

export interface WalkthroughResult {
  markdown?: string;
  html?: string;
  suggestions: Suggestion[];
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
  addLabHost: (body: LabHostCreate) =>
    request<LabHostCreated>("/lab", { method: "POST", body: JSON.stringify(body) }),
  removeLabHost: (name: string, purge: boolean) =>
    request<void>(`/lab/${encodeURIComponent(name)}?purge=${purge}`, { method: "DELETE" }),

  listRuns: () => request<RunRecord[]>("/runs"),
  getRun: (runId: string) => request<RunRecord>(`/runs/${runId}`),
  getRunReport: (runId: string) => request<{ markdown: string }>(`/runs/${runId}/report`),
  analyzeRun: (runId: string) => request<RunRecord>(`/runs/${runId}/analyze`, { method: "POST" }),
  reviewFinding: (runId: string, findingId: string, status: FindingStatus) =>
    request<RunRecord>(`/runs/${runId}/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  listAudit: () => request<PolicyViolation[]>("/audit"),

  verifyRun: (runId: string) => request<EvidenceVerification>(`/runs/${runId}/verify`),

  createScan: (target: string, plugin: string, options: Record<string, string>) =>
    request<ScanCreated>("/scans", {
      method: "POST",
      body: JSON.stringify({ target, plugin, options }),
    }),
  getScan: (jobId: string) => request<ScanStatus>(`/scans/${jobId}`),

  createWalkthrough: (body: WalkthroughRequest) =>
    request<WalkthroughResult>("/walkthroughs", { method: "POST", body: JSON.stringify(body) }),

  listPlaybooks: () => request<Playbook[]>("/playbooks"),
  getPlaybook: (name: string) => request<Playbook>(`/playbooks/${encodeURIComponent(name)}`),
  runPlaybook: (name: string, target: string) =>
    request<PlaybookRunCreated>(`/playbooks/${encodeURIComponent(name)}/run`, {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  listAttackSessions: () => request<AttackSession[]>("/attack-sessions"),
  getAttackSession: (name: string) =>
    request<AttackSession>(`/attack-sessions/${encodeURIComponent(name)}`),
  createAttackSession: (body: { name: string; description?: string; engagement?: string | null }) =>
    request<AttackSession>("/attack-sessions", { method: "POST", body: JSON.stringify(body) }),
  addAttackSessionStage: (name: string, run_id: string, label?: string) =>
    request<AttackSession>(`/attack-sessions/${encodeURIComponent(name)}/stages`, {
      method: "POST",
      body: JSON.stringify({ run_id, label: label ?? "" }),
    }),
  getAttackSessionReport: (name: string, format: "markdown" | "html" = "markdown") =>
    request<{ markdown?: string; html?: string }>(
      `/attack-sessions/${encodeURIComponent(name)}/report?format=${format}`,
    ),

  getSettings: () => request<AppSettings>("/settings"),
  updateSettings: (body: AppSettings) =>
    request<AppSettings>("/settings", { method: "PUT", body: JSON.stringify(body) }),
};
