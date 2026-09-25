export type TargetKind = "host" | "url" | "path";
export type TargetType = "network" | "web" | "api" | "kubernetes" | "container" | "source-code";
export type TargetEnvironment = "local-lab" | "staging" | "production";

export interface Target {
  name: string;
  kind: TargetKind;
  address: string;
  allowed_plugins: string[];
  notes: string | null;
  type: TargetType | null;
  environment: TargetEnvironment;
  excluded: boolean;
  exclusion_reason: string | null;
  max_concurrent: number | null;
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

export interface KindClusterInfo {
  name: string;
  context: string;
}

export interface KindCreated {
  cluster: KindClusterInfo;
  kubeconfig_path: string;
  registered_target: Target | null;
  registration_warning: string | null;
}

export interface PublishedPort {
  service: string;
  host_port: number;
  container_port: number;
}

export interface LabScenario {
  id: string;
  path: string;
  running: boolean;
  published_ports: PublishedPort[];
}

export interface VulhubStartResult {
  scenario: LabScenario;
  registered_target: Target | null;
  registration_warning: string | null;
  warning: string;
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
  attack_technique_ids: string[];
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
  artifacts: { id: string; type: string; description: string; path: string | null; sha256: string | null }[];
  cves: string[];
}

export interface PluginOption {
  name: string;
  description: string;
  required: boolean;
  default: string | null;
  choices: string[] | null;
}

export interface PluginInfo {
  name: string;
  version: string;
  description: string;
  required_tool: string;
  tool_available: boolean;
  expected_kind: TargetKind | null;
  kind_hint: string | null;
  options: PluginOption[] | null;
  accepts_extra_options: boolean;
  source: string;
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

// --- Validation primitives (docs/handbook.md §15) ---
export type ValidationLevel = "detection" | "validation" | "execution";
export type PreconditionStatus = "met" | "unmet" | "unknown";

export interface PrimitiveDescriptor {
  id: string;
  category: string;
  description: string;
  action_class: string;
  max_level: ValidationLevel;
  capabilities: string[];
  requires_external_network: boolean;
  requires_persistence: boolean;
}

export interface PrimitiveInfo {
  descriptor: PrimitiveDescriptor;
  options: { name: string; description: string; required: boolean }[];
}

export interface Precondition {
  id: string;
  description: string;
  status: PreconditionStatus;
  detail: string | null;
}

export interface PrimitiveObservation {
  id: string;
  type: string;
  detail: string;
  timestamp: string;
  provenance: { kind: "observed" | "inferred"; primitive: string };
}

export interface Claim {
  id: string;
  statement: string;
  confidence: "tentative" | "probable" | "confirmed";
  supported_by: string[];
}

export interface ManagedResource {
  id: string;
  type: string;
  owner: string;
  description: string;
  cleanup_required: boolean;
  status: string;
}

export interface PrimitiveEvidence {
  evidence_id: string;
  target: string;
  primitive: string;
  observations: PrimitiveObservation[];
  artifacts: { id: string; type: string; description: string; path: string | null; sha256: string | null }[];
  findings: Finding[];
  claims: Claim[];
}

export interface PrimitiveRunRecord {
  run_id: string;
  primitive: string;
  category: string;
  target: string;
  created_at: string;
  requested_level: ValidationLevel;
  level_reached: ValidationLevel;
  preconditions: { preconditions: Precondition[] };
  evidence: PrimitiveEvidence | null;
  resources: ManagedResource[];
  cleanup: { resource_id: string; attempted: boolean; verified_absent: boolean; error: string | null }[];
  residual_resources: ManagedResource[];
  notes: string;
}

export interface CveExposure {
  cve: string;
  scan_plugins: string[];
  primitive_ids: string[];
  highest_validation: string | null;
  confirmed_validation: boolean;
  manual_run_ids: string[];
  manual_artifact_count: number;
}

export interface EngagementJson {
  scope_label: string;
  targets: string[];
  scan_runs: number;
  primitive_runs: number;
  cve_exposure: CveExposure[];
}

// --- Attack operations (docs/handbook.md §15) ---
export type AttackPhase =
  | "recon"
  | "initial-access"
  | "execution"
  | "privilege-escalation"
  | "credential-access"
  | "discovery"
  | "lateral-movement"
  | "persistence"
  | "impact";

export type ActionKind = "scan" | "manual" | "pivot";
export type ActionStatus = "planned" | "approved" | "completed" | "rejected";
export type AttackNodeState =
  | "known"
  | "candidate"
  | "planned"
  | "approved"
  | "running"
  | "succeeded"
  | "failed"
  | "skipped";
export type Capability = "read-only" | "state-changing" | "credential-related" | "network-pivot" | "persistence";

export interface AttackNode {
  id: string;
  target: string;
  label: string;
  state: AttackNodeState;
  attack_technique_ids: string[];
}

export interface AttackEdge {
  source: string;
  destination: string;
  relationship: string;
  capabilities: Capability[];
  attack_technique_ids: string[];
}

export interface OperationAction {
  id: string;
  name: string;
  phase: AttackPhase;
  kind: ActionKind;
  target: string;
  plugin: string | null;
  options: Record<string, unknown>;
  prerequisites: string[];
  capabilities: Capability[];
  requires: string[];
  provides: string[];
  status: ActionStatus;
  run_id: string | null;
  attack_technique_ids: string[];
}

export interface Approval {
  id: string;
  action_id: string;
  approved_by: string;
  approved_at: string;
  note: string;
}

export interface AttackOperation {
  name: string;
  objective: string;
  engagement: string | null;
  nodes: AttackNode[];
  edges: AttackEdge[];
  actions: OperationAction[];
  approvals: Approval[];
}

export const api = {
  listTargets: () => request<Target[]>("/targets"),
  addTarget: (target: Target) =>
    request<Target>("/targets", { method: "POST", body: JSON.stringify(target) }),
  removeTarget: (name: string) =>
    request<void>(`/targets/${encodeURIComponent(name)}`, { method: "DELETE" }),
  excludeTarget: (name: string, reason: string) =>
    request<Target>(`/targets/${encodeURIComponent(name)}/exclude`, {
      method: "POST",
      body: JSON.stringify({ reason: reason || null }),
    }),
  includeTarget: (name: string) =>
    request<Target>(`/targets/${encodeURIComponent(name)}/include`, { method: "POST" }),

  listPlugins: () => request<PluginInfo[]>("/plugins"),

  listLab: () => request<LabHost[]>("/lab"),
  addLabHost: (body: LabHostCreate) =>
    request<LabHostCreated>("/lab", { method: "POST", body: JSON.stringify(body) }),
  removeLabHost: (name: string, purge: boolean) =>
    request<void>(`/lab/${encodeURIComponent(name)}?purge=${purge}`, { method: "DELETE" }),

  listKindClusters: () => request<KindClusterInfo[]>("/lab/kind"),
  createKindCluster: (name: string, registerTarget: boolean) =>
    request<KindCreated>("/lab/kind", {
      method: "POST",
      body: JSON.stringify({ name, register_target: registerTarget }),
    }),
  deleteKindCluster: (name: string, purge: boolean) =>
    request<void>(`/lab/kind/${encodeURIComponent(name)}?purge=${purge}`, { method: "DELETE" }),

  listVulhubScenarios: () => request<LabScenario[]>("/lab/provider/scenarios"),
  vulhubStatus: (scenario: string) =>
    request<LabScenario>(`/lab/provider/status?scenario=${encodeURIComponent(scenario)}`),
  startVulhub: (scenario: string, registerTarget: boolean) =>
    request<VulhubStartResult>("/lab/provider/start", {
      method: "POST",
      body: JSON.stringify({ scenario, register_target: registerTarget }),
    }),
  stopVulhub: (scenario: string) =>
    request<void>("/lab/provider/stop", { method: "POST", body: JSON.stringify({ scenario }) }),
  cleanupVulhub: (scenario: string, purge: boolean) =>
    request<void>("/lab/provider/cleanup", {
      method: "POST",
      body: JSON.stringify({ scenario, purge }),
    }),

  listRuns: () => request<RunRecord[]>("/runs"),
  getRun: (runId: string) => request<RunRecord>(`/runs/${runId}`),
  // Manual exploit-step import: multipart (form fields + artifact uploads), so
  // this bypasses the JSON `request` helper and lets the browser set the
  // multipart boundary itself.
  importRun: async (form: FormData): Promise<RunRecord> => {
    const res = await fetch("/api/runs/import", { method: "POST", body: form });
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as { detail?: string };
      throw new Error(body.detail || `${res.status} ${res.statusText}`);
    }
    return res.json() as Promise<RunRecord>;
  },
  getRunReport: (runId: string) => request<{ markdown: string }>(`/runs/${runId}/report`),
  // PDF is binary, not JSON -- the browser downloads it directly from this
  // URL (e.g. via an <a href> or window.open) rather than through fetch().
  runReportPdfUrl: (runId: string) => `/api/runs/${encodeURIComponent(runId)}/report?format=pdf`,
  analyzeRun: (runId: string) => request<RunRecord>(`/runs/${runId}/analyze`, { method: "POST" }),
  tagRunCves: (runId: string, cves: string[], remove: boolean) =>
    request<RunRecord>(`/runs/${encodeURIComponent(runId)}/cves`, {
      method: "PATCH",
      body: JSON.stringify({ cves, remove }),
    }),
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
  attackSessionReportPdfUrl: (name: string) =>
    `/api/attack-sessions/${encodeURIComponent(name)}/report?format=pdf`,

  listPrimitives: () => request<PrimitiveInfo[]>("/primitives"),
  runPrimitive: (body: {
    primitive: string;
    target: string;
    level: ValidationLevel;
    options: Record<string, string>;
  }) => request<PrimitiveRunRecord>("/primitives/run", { method: "POST", body: JSON.stringify(body) }),
  listPrimitiveRuns: () => request<PrimitiveRunRecord[]>("/primitive-runs"),
  getPrimitiveRun: (runId: string) => request<PrimitiveRunRecord>(`/primitive-runs/${encodeURIComponent(runId)}`),
  getPrimitiveRunReport: (runId: string, format: "markdown" | "html" = "markdown") =>
    request<{ markdown?: string; html?: string }>(
      `/primitive-runs/${encodeURIComponent(runId)}/report?format=${format}`,
    ),
  primitiveRunReportPdfUrl: (runId: string) =>
    `/api/primitive-runs/${encodeURIComponent(runId)}/report?format=pdf`,

  getEngagementReport: (
    scope: { target?: string; engagement?: string },
    format: "markdown" | "html" = "markdown",
  ) => {
    const params = new URLSearchParams({ format });
    if (scope.target) params.set("target", scope.target);
    if (scope.engagement) params.set("engagement", scope.engagement);
    return request<{ markdown?: string; html?: string }>(`/reports/engagement?${params}`);
  },
  getEngagementCveMatrix: (scope: { target?: string; engagement?: string }) => {
    const params = new URLSearchParams({ format: "json" });
    if (scope.target) params.set("target", scope.target);
    if (scope.engagement) params.set("engagement", scope.engagement);
    return request<EngagementJson>(`/reports/engagement?${params}`);
  },
  engagementReportPdfUrl: (scope: { target?: string; engagement?: string }) => {
    const params = new URLSearchParams({ format: "pdf" });
    if (scope.target) params.set("target", scope.target);
    if (scope.engagement) params.set("engagement", scope.engagement);
    return `/api/reports/engagement?${params}`;
  },

  getSettings: () => request<AppSettings>("/settings"),
  updateSettings: (body: AppSettings) =>
    request<AppSettings>("/settings", { method: "PUT", body: JSON.stringify(body) }),

  listOperations: () => request<AttackOperation[]>("/operations"),
  getOperation: (name: string) => request<AttackOperation>(`/operations/${encodeURIComponent(name)}`),
  createOperation: (body: { name: string; objective?: string; engagement?: string | null }) =>
    request<AttackOperation>("/operations", { method: "POST", body: JSON.stringify(body) }),
  addOperationNode: (
    name: string,
    body: { node_id: string; target: string; label?: string; attack_technique_ids?: string[] },
  ) =>
    request<AttackOperation>(`/operations/${encodeURIComponent(name)}/nodes`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  addOperationEdge: (
    name: string,
    body: {
      source: string;
      destination: string;
      capabilities?: Capability[] | null;
      attack_technique_ids?: string[];
    },
  ) =>
    request<AttackOperation>(`/operations/${encodeURIComponent(name)}/edges`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  addOperationAction: (
    name: string,
    body: {
      id: string;
      name: string;
      phase: AttackPhase;
      kind: ActionKind;
      target: string;
      plugin?: string | null;
      options?: Record<string, unknown>;
      prerequisites?: string[];
      capabilities?: Capability[];
      requires?: string[];
      provides?: string[];
      attack_technique_ids?: string[];
    },
  ) =>
    request<AttackOperation>(`/operations/${encodeURIComponent(name)}/actions`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  approveOperationAction: (name: string, actionId: string, approved_by: string, note?: string) =>
    request<AttackOperation>(
      `/operations/${encodeURIComponent(name)}/actions/${encodeURIComponent(actionId)}/approve`,
      { method: "POST", body: JSON.stringify({ approved_by, note: note ?? "" }) },
    ),
  executeOperationAction: (
    name: string,
    actionId: string,
    body: { command?: string; output?: string; tool?: string; tool_version?: string; returncode?: number },
  ) =>
    request<AttackOperation>(
      `/operations/${encodeURIComponent(name)}/actions/${encodeURIComponent(actionId)}/execute`,
      { method: "POST", body: JSON.stringify(body) },
    ),
};
