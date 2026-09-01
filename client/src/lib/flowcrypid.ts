// FlowCrypid dashboard contracts: keep the UI coupled to an explicit API shape with no implicit escape hatches.
export type Severity = "P0" | "P1" | "P2" | "P3" | "P4" | "P5";
export type HealthState = "healthy" | "degraded" | "offline";

export interface HealthComponents {
  ml_anomaly_model: "ready" | "missing" | "error" | string;
  baseline_store?: "ready" | "missing" | "error" | string;
  detector_validation?: string;
  worker_execution?: string;
  [key: string]: string | undefined;
}

export interface HealthResponse {
  status: HealthState | string;
  components: HealthComponents;
  version?: string;
}

export interface FlowFinding {
  id: string;
  title: string;
  tier: Severity;
  detector_id?: string;
  detector_version?: string;
  confidence?: number;
  risk_score: number;
  source_ip: string;
  dest_ip: string;
  dest_port?: number;
  protocol?: number;
  first_seen?: number | string;
  last_seen?: number | string;
  evidence: string[];
  contributing_signals: string[];
  explanation?: string[];
  calibrated_probability?: number;
  calibration_method?: string;
}

export interface Incident {
  id?: string;
  source_ip?: string;
  title?: string;
  severity?: Severity;
  risk_score?: number;
  first_seen?: number | string;
  last_seen?: number | string;
}

export interface UploadResponse {
  capture_id?: string;
  parsed_flows: number;
  total_packets?: number;
  unsupported_packets: number;
  findings: FlowFinding[];
  incidents: Incident[];
  capture_started_at?: number | string;
  capture_ended_at?: number | string;
  error?: string | null;
}

export type IncidentStatus = "new" | "acknowledged" | "investigating" | "resolved" | "false_positive";

export interface IncidentRecord {
  id: string;
  source_ip: string;
  title: string;
  severity: Severity;
  risk_score: number;
  first_seen?: number | string | null;
  last_seen?: number | string | null;
  status: IncidentStatus;
  assignee?: string | null;
  notes: string;
}

export interface CaptureSummary {
  id: string;
  filename: string;
  size_bytes: number;
  parsed_flows: number;
  total_packets: number;
  unsupported_packets: number;
  started_at?: number | null;
  ended_at?: number | null;
  created_at: number;
}

export interface JobResponse {
  id: string;
  status: "queued" | "processing" | "completed" | "failed" | string;
  filename: string;
  size_bytes: number;
  progress: number;
  error?: string | null;
  result?: UploadResponse | null;
  created_at: number;
  updated_at: number;
  started_at?: number | null;
  completed_at?: number | null;
}

export interface TimelinePoint {
  label: string;
  timestamp: number;
  findings: number;
  highRisk: number;
  totalRisk: number;
}

export const severityOrder: Severity[] = ["P0", "P1", "P2", "P3", "P4", "P5"];

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && severityOrder.includes(value as Severity);
}

export function normalizeFinding(input: Partial<FlowFinding>, index: number): FlowFinding {
  const tier = isSeverity(input.tier) ? input.tier : "P2";
  return {
    id: input.id || `finding-${index + 1}`,
    title: input.title || "Unclassified network finding",
    tier,
    detector_id: input.detector_id,
    detector_version: input.detector_version,
    confidence: Number.isFinite(input.confidence) ? Number(input.confidence) : undefined,
    risk_score: Number.isFinite(input.risk_score) ? Number(input.risk_score) : 0,
    source_ip: input.source_ip || "unknown",
    dest_ip: input.dest_ip || "unknown",
    dest_port: input.dest_port,
    protocol: input.protocol,
    first_seen: input.first_seen,
    last_seen: input.last_seen,
    evidence: Array.isArray(input.evidence) ? input.evidence.map(String) : [],
    contributing_signals: Array.isArray(input.contributing_signals) ? input.contributing_signals.map(String) : [],
    explanation: Array.isArray(input.explanation) ? input.explanation.map(String) : [],
    calibrated_probability: Number.isFinite(input.calibrated_probability) ? Number(input.calibrated_probability) : undefined,
    calibration_method: input.calibration_method,
  };
}

export function asTimestamp(value: number | string | undefined, fallback: number): number {
  if (typeof value === "number" && Number.isFinite(value)) return value > 10_000_000_000 ? Math.round(value / 1000) : value;
  if (typeof value === "string") {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric > 10_000_000_000 ? Math.round(numeric / 1000) : numeric;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return Math.round(parsed / 1000);
  }
  return fallback;
}

export function formatTime(value: number | string | undefined): string {
  const timestamp = asTimestamp(value, Date.now() / 1000);
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(timestamp * 1000));
}
