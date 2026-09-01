// FlowCrypid SOC dashboard: dark telemetry interface, typed API contracts, severity-first analyst workflow.
import { useEffect, useMemo, useState } from "react";
import { Activity, AlertOctagon, AlertTriangle, Check, ChevronRight, Download, FileUp, Filter, HardDrive, LoaderCircle, Network, Search, Server, Shield, X } from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getHealth, login, logout, getCurrentUser, uploadPcap, getAnalysisJob, getCaptures, getIncidents, updateIncident, API_BASE_URL, type AuthUser } from "@/lib/api";
import { asTimestamp, formatTime, normalizeFinding, severityOrder, type CaptureSummary, type FlowFinding, type HealthResponse, type IncidentRecord, type IncidentStatus, type Severity, type TimelinePoint, type UploadResponse } from "@/lib/flowcrypid";
import "./index.css";

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const severityLabels: Array<"ALL" | Severity> = ["ALL", ...severityOrder];
const severityColors: Record<Severity, string> = { P0: "#ff7167", P1: "#ffb45f", P2: "#00dbe9", P3: "#b7d93c", P4: "#9ca6b6", P5: "#7d8cff" };

const demoResults: UploadResponse = {
  parsed_flows: 1284,
  total_packets: 38912,
  unsupported_packets: 41,
  incidents: [{ id: "INC-2401", source_ip: "192.168.45.211", severity: "P0", risk_score: 95 }, { id: "INC-2397", source_ip: "10.0.52.88", severity: "P1", risk_score: 82 }],
  findings: [
    { id: "F-2401", title: "After-hours data transfer", tier: "P0", risk_score: 95, source_ip: "192.168.45.211", dest_ip: "185.44.91.18", dest_port: 443, first_seen: 1716990000, last_seen: 1716997200, evidence: ["4.2 GB outbound in 12 minutes", "Low temporal jitter across 48 flows"], contributing_signals: ["P0_LOW_AND_SLOW_EXFIL", "ML_ANOMALY"] },
    { id: "F-2397", title: "Rare external destination", tier: "P1", risk_score: 82, source_ip: "10.0.52.88", dest_ip: "91.211.88.4", dest_port: 8443, first_seen: 1716991200, last_seen: 1716994800, evidence: ["First-seen destination for device", "Destination is not allowlisted"], contributing_signals: ["P1_RARE_EXTERNAL_DESTINATION", "BASELINE_DEVIATION"] },
    { id: "F-2392", title: "Unusual port activity", tier: "P2", risk_score: 65, source_ip: "172.16.0.42", dest_ip: "8.8.8.8", dest_port: 5353, first_seen: 1716985800, last_seen: 1716991200, evidence: ["Outbound DNS traffic outside usual window"], contributing_signals: ["P2_DNS_ANOMALY"] },
    { id: "F-2388", title: "Periodic beaconing", tier: "P3", risk_score: 49, source_ip: "192.168.12.19", dest_ip: "45.133.22.9", dest_port: 443, first_seen: 1716982200, last_seen: 1716990000, evidence: ["Regular 60 second connection cadence"], contributing_signals: ["P3_BEACONING"] },
    { id: "F-2381", title: "Internal staging volume", tier: "P4", risk_score: 32, source_ip: "10.0.3.14", dest_ip: "10.0.4.20", dest_port: 445, first_seen: 1716978600, last_seen: 1716985800, evidence: ["Large internal-to-internal transfer"], contributing_signals: ["P4_STAGING"] },
  ],
};

function statusLabel(health: HealthResponse | null, loading: boolean): string { if (loading) return "CHECKING"; if (!health) return API_BASE_URL ? "OFFLINE" : "DEMO MODE"; return health.status.toUpperCase(); }
function severityClass(value: Severity): string { return `severity severity-${value.toLowerCase()}`; }
function csvCell(value: unknown): string { return `"${String(value ?? "").replaceAll('"', '""')}"`; }
function exportFindings(findings: FlowFinding[]): void {
  const header = ["id", "severity", "detector_id", "detector_version", "confidence", "title", "risk_score", "calibrated_probability", "calibration_method", "source_ip", "dest_ip", "dest_port", "first_seen", "last_seen", "signals", "evidence", "explanation"];
  const rows = findings.map((finding) => [finding.id, finding.tier, finding.detector_id ?? "unknown", finding.detector_version ?? "unknown", finding.confidence ?? "", finding.title, finding.risk_score, finding.calibrated_probability ?? "", finding.calibration_method ?? "raw-score-fallback", finding.source_ip, finding.dest_ip, finding.dest_port, finding.first_seen, finding.last_seen, finding.contributing_signals.join(" | "), finding.evidence.join(" | "), finding.explanation?.join(" | ") ?? ""]);
  const csv = [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `flowcrypid-findings-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function exportFindingsJson(findings: FlowFinding[]): void {
  const blob = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `flowcrypid-findings-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function buildTimeline(findings: FlowFinding[]): TimelinePoint[] {
  if (!findings.length) return [];
  const timestamps = findings.map((finding, index) => asTimestamp(finding.first_seen, Date.now() / 1000 - (findings.length - index) * 3600));
  const minimum = Math.min(...timestamps);
  const buckets = new Map<number, TimelinePoint>();
  timestamps.forEach((timestamp, index) => {
    const hour = Math.floor(timestamp / 3600) * 3600;
    const finding = findings[index];
    const point = buckets.get(hour) ?? { label: formatTime(hour), timestamp: hour, findings: 0, highRisk: 0, totalRisk: 0 };
    point.findings += 1;
    point.totalRisk += finding.risk_score;
    if (finding.tier === "P0" || finding.tier === "P1") point.highRisk += 1;
    buckets.set(hour, point);
  });
  return Array.from(buckets.values()).sort((a, b) => a.timestamp - b.timestamp).map((point) => ({ ...point, label: point.timestamp === Math.floor(minimum / 3600) * 3600 ? "START" : point.label }));
}

function Metric({ icon, label, value, detail, accent }: { icon: React.ReactNode; label: string; value: string | number; detail: string; accent?: string }) {
  return <div className="metric-card"><div className="metric-label">{icon}{label}</div><strong style={{ color: accent }}>{value}</strong><span>{detail}</span></div>;
}

export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [results, setResults] = useState<UploadResponse | null>(demoResults);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [jobStatus, setJobStatus] = useState<string | null>(null);
  const [jobProgress, setJobProgress] = useState(0);
  const [healthLoading, setHealthLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<"ALL" | Severity>("ALL");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<FlowFinding | null>(demoResults.findings[0]);
  const [showUploader, setShowUploader] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [captureHistoryLoading, setCaptureHistoryLoading] = useState(false);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [incidentFilter, setIncidentFilter] = useState<IncidentStatus | "all">("all");
  const [incidentLoading, setIncidentLoading] = useState(false);
  const [authToken, setAuthToken] = useState(() => localStorage.getItem("flowcrypid_token") ?? "");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    getHealth(controller.signal).then(setHealth).catch(() => setHealth(null)).finally(() => setHealthLoading(false));
    if (authToken) {
      getCurrentUser(authToken, controller.signal).then(setUser).catch(() => { localStorage.removeItem("flowcrypid_token"); setAuthToken(""); }).catch(() => undefined);
      setCaptureHistoryLoading(true);
      getCaptures(authToken, controller.signal).then(setCaptures).catch(() => setCaptures([])).finally(() => setCaptureHistoryLoading(false));
      setIncidentLoading(true);
      getIncidents(authToken, undefined, controller.signal).then(setIncidents).catch(() => setIncidents([])).finally(() => setIncidentLoading(false));
    } else {
      setUser(null);
      setCaptures([]);
      setIncidents([]);
    }
    return () => controller.abort();
  }, [authToken]);

  const findings = useMemo(() => (results?.findings ?? []).map(normalizeFinding), [results]);
  const filteredFindings = useMemo(() => findings.filter((finding) => (severity === "ALL" || finding.tier === severity) && `${finding.source_ip} ${finding.dest_ip} ${finding.title}`.toLowerCase().includes(query.toLowerCase())), [findings, query, severity]);
  const timeline = useMemo(() => buildTimeline(filteredFindings), [filteredFindings]);
  const highRisk = findings.filter((finding) => finding.tier === "P0" || finding.tier === "P1").length;
  const avgRisk = findings.length ? Math.round(findings.reduce((sum, finding) => sum + finding.risk_score, 0) / findings.length) : 0;

  async function handleLogin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthLoading(true); setError(null);
    try {
      const response = await login(loginEmail, loginPassword);
      localStorage.setItem("flowcrypid_token", response.access_token);
      setAuthToken(response.access_token); setUser(response.user); setShowLogin(false);
    } catch (loginError) { setError(loginError instanceof Error ? loginError.message : "Unable to sign in."); }
    finally { setAuthLoading(false); }
  }

  async function handleLogout() {
    if (authToken) await logout(authToken).catch(() => undefined);
    localStorage.removeItem("flowcrypid_token"); setAuthToken(""); setUser(null);
  }

  async function handleUpload(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) return;
    if (!authToken) { setShowLogin(true); setError("Sign in before uploading a capture."); return; }
    if (file.size > MAX_FILE_SIZE) { setError("This capture exceeds the 50 MB client limit. The API must enforce the same limit server-side."); return; }
    setLoading(true); setJobStatus("queued"); setJobProgress(0); setError(null);
    try {
      const submitted = await uploadPcap(file, authToken);
      setJobStatus(submitted.status); setJobProgress(submitted.progress);
      let current = submitted;
      for (let attempt = 0; attempt < 120 && current.status !== "completed" && current.status !== "failed"; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 500));
        current = await getAnalysisJob(submitted.id, authToken);
        setJobStatus(current.status); setJobProgress(current.progress);
      }
      if (current.status === "failed") throw new Error(current.error || "Capture analysis failed.");
      if (current.status !== "completed" || !current.result) throw new Error("Capture analysis timed out; check the job status before retrying.");
      setResults(current.result); setSelected(current.result.findings[0] ?? null); setShowUploader(false);
      getCaptures(authToken).then(setCaptures).catch(() => undefined);
      getIncidents(authToken).then(setIncidents).catch(() => undefined);
    } catch (uploadError) { setError(uploadError instanceof Error ? uploadError.message : "Unable to connect to the FlowCrypid API."); }
    finally { setLoading(false); }
  }

  const visibleIncidents = incidentFilter === "all" ? incidents : incidents.filter((incident) => incident.status === incidentFilter);

  async function handleIncidentUpdate(incident: IncidentRecord, update: Partial<Pick<IncidentRecord, "status" | "assignee" | "notes">>) {
    if (!authToken) return;
    try { const updated = await updateIncident(authToken, incident.id, update); setIncidents((current) => current.map((item) => item.id === updated.id ? updated : item)); } catch (incidentError) { setError(incidentError instanceof Error ? incidentError.message : "Unable to update incident."); }
  }

  return <div className="soc-app">
    <a className="skip-link" href="#main-content">Skip to main content</a>
    <header className="soc-header"><div className="wordmark"><div className="mark"><span>F</span></div><div><strong>FLOWCRYPID</strong><small>THREAT INTELLIGENCE CONSOLE</small></div></div><div className="header-center"><span className="live-dot"/>LIVE MONITORING <span className="header-divider"/> CAPTURE: <b>{results === demoResults ? "DEMO SNAPSHOT" : "API RESULT"}</b></div><div className="header-right"><span className={`status-chip ${health ? "status-good" : "status-warn"}`} role="status" aria-live="polite"><i/> API {statusLabel(health, healthLoading)}</span>{user ? <button className="auth-chip" onClick={handleLogout} title="Sign out" aria-label={`Sign out ${user.email}`}>{user.email} · SIGN OUT</button> : <button className="auth-chip" onClick={() => setShowLogin(!showLogin)}>{showLogin ? "CLOSE LOGIN" : "SIGN IN"}</button>}<button className="auth-chip" onClick={() => setShowHistory(!showHistory)} disabled={!user} aria-pressed={showHistory}>HISTORY {captures.length ? `· ${captures.length}` : ""}</button><button className="icon-button" title="Upload a PCAP" aria-label="Upload a PCAP" onClick={() => setShowUploader(!showUploader)}><FileUp size={16}/></button></div></header>
    <div className="soc-layout"><aside className="soc-sidebar"><div className="sidebar-top"><span className="sidebar-kicker">ACTIVE SCOPE</span><strong>ENTERPRISE / EDGE-01</strong><span className="sidebar-meta">192.168.0.0/16 <i/> 12 MIN WINDOW</span></div><nav><a className="selected" href="#overview"><Activity size={15}/> Overview <span>01</span></a><a href="#findings"><AlertOctagon size={15}/> Findings <span>{findings.length}</span></a><a href="#timeline"><Network size={15}/> Timeline</a><a href="#investigation"><Search size={15}/> Investigation</a></nav><div className="sidebar-status"><span className="sidebar-kicker">PIPELINE STATUS</span><div><i className="dot green"/>PCAP PARSER <b>READY</b></div><div><i className="dot cyan"/>ML MODEL <b>{health?.components.ml_anomaly_model?.toUpperCase() ?? "DEMO"}</b></div><div><i className="dot amber"/>BASELINES <b>LOCAL</b></div></div><div className="sidebar-footer"><Shield size={15}/> P0–P5 DETECTION GRID <span>v2.4.0</span></div></aside>
      <main className="soc-main" id="main-content" tabIndex={-1}><section className="dashboard-title" id="overview"><div><span className="eyebrow">SECURITY OPERATIONS / OVERVIEW</span><h1>Threat telemetry <em>at a glance.</em></h1><p>Behavioral anomalies and exfiltration signals surfaced from the active capture.</p></div><div className="title-actions"><button className="outline-button" onClick={() => exportFindings(filteredFindings)}><Download size={15}/> EXPORT CSV</button><button className="outline-button" onClick={() => exportFindingsJson(filteredFindings)}><Download size={15}/> JSON</button><button className="primary-button" onClick={() => setShowUploader(true)}><FileUp size={15}/> INGEST PCAP</button></div></section>
        {error && <div className="error-banner" role="alert" aria-live="assertive"><AlertTriangle size={16}/><span>{error}</span><button onClick={() => setError(null)} aria-label="Dismiss error"><X size={15}/></button></div>}
        <section className={`trust-banner ${results === demoResults ? "trust-demo" : "trust-live"}`} aria-label="Data provenance and detector status"><div className="trust-icon"><Shield size={16}/></div><div><strong>{results === demoResults ? "DEMO SNAPSHOT — DO NOT TREAT AS LIVE TELEMETRY" : "API RESULT — CAPTURE-SPECIFIC EVIDENCE"}</strong><p>{results === demoResults ? "The dashboard is showing seeded review data because no analyzed capture is loaded. Sign in and ingest an approved PCAP to produce real results." : "Findings below are derived from the connected API capture. Validate detector output against analyst context before response."}</p></div><div className="trust-meta"><span>DETECTOR <b>{health?.components.detector_validation?.toUpperCase() ?? "UNVALIDATED"}</b></span><span>WORKER <b>{health?.components.worker_execution?.toUpperCase() ?? "LOCAL"}</b></span></div></section>
        {showLogin && <form className="auth-panel" onSubmit={handleLogin}><div><span className="eyebrow">AUTHENTICATED ACCESS</span><h2>Sign in to ingest captures</h2><p>Uploads require an analyst or administrator session. Credentials are configured by the deployment owner.</p></div><label>Email<input type="email" value={loginEmail} onChange={(event) => setLoginEmail(event.target.value)} autoComplete="username" required /></label><label>Password<input type="password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} autoComplete="current-password" required /></label><button className="primary-button" disabled={authLoading}>{authLoading ? "SIGNING IN" : "SIGN IN"}</button></form>}
        {user && <section className="panel incident-panel" aria-labelledby="incident-heading"><div className="panel-heading"><div><span className="eyebrow">TRIAGE QUEUE</span><h2 id="incident-heading">Incident lifecycle</h2></div><div className="filter-group"><button className={incidentFilter === "all" ? "filter-button active" : "filter-button"} onClick={() => setIncidentFilter("all")}>ALL</button>{(["new", "acknowledged", "investigating", "resolved", "false_positive"] as IncidentStatus[]).map((status) => <button key={status} className={incidentFilter === status ? "filter-button active" : "filter-button"} onClick={() => setIncidentFilter(status)}>{status.replace("_", " ").toUpperCase()}</button>)}</div></div>{incidentLoading ? <div className="empty-state">Loading incidents…</div> : visibleIncidents.length === 0 ? <div className="empty-state">No incidents match this lifecycle filter.</div> : <div className="findings-table-wrap"><table className="findings-table"><thead><tr><th>SEVERITY</th><th>INCIDENT</th><th>STATUS</th><th>ASSIGNEE</th><th>UPDATE</th></tr></thead><tbody>{visibleIncidents.map((incident) => <tr key={incident.id}><td><span className={severityClass(incident.severity)}>{incident.severity}</span></td><td><strong>{incident.title}</strong><small>{incident.id} · {incident.source_ip}</small></td><td><select aria-label={`Status for ${incident.id}`} value={incident.status} onChange={(event) => handleIncidentUpdate(incident, { status: event.target.value as IncidentStatus })}><option value="new">NEW</option><option value="acknowledged">ACKNOWLEDGED</option><option value="investigating">INVESTIGATING</option><option value="resolved">RESOLVED</option><option value="false_positive">FALSE POSITIVE</option></select></td><td><input aria-label={`Assignee for ${incident.id}`} defaultValue={incident.assignee ?? ""} placeholder="analyst" onBlur={(event) => { if (event.target.value !== (incident.assignee ?? "")) handleIncidentUpdate(incident, { assignee: event.target.value || null }); }}/></td><td><button className="outline-button small" onClick={() => handleIncidentUpdate(incident, { notes: incident.notes ? `${incident.notes}\nReviewed ${new Date().toISOString()}` : `Reviewed ${new Date().toISOString()}` })}>ADD REVIEW NOTE</button></td></tr>)}</tbody></table></div>}</section>}
        {showHistory && <section className="panel capture-history-panel" aria-labelledby="capture-history-heading"><div className="panel-heading"><div><span className="eyebrow">AUTHORIZED CAPTURES</span><h2 id="capture-history-heading">Capture history</h2></div><span className="panel-tag">{captureHistoryLoading ? "LOADING" : `${captures.length} CAPTURES`}</span></div>{!user ? <div className="empty-state">Sign in to view authorized capture history.</div> : captureHistoryLoading ? <div className="empty-state">Loading capture history…</div> : captures.length === 0 ? <div className="empty-state">No completed captures are associated with this account.</div> : <div className="findings-table-wrap"><table className="findings-table capture-history-table"><thead><tr><th>CAPTURE</th><th>FLOWS</th><th>PACKETS</th><th>SIZE</th><th>CREATED</th></tr></thead><tbody>{captures.map((capture) => <tr key={capture.id}><td><strong>{capture.id}</strong><small>{capture.filename}</small></td><td>{capture.parsed_flows.toLocaleString()}</td><td>{capture.total_packets.toLocaleString()}</td><td>{(capture.size_bytes / 1024 / 1024).toFixed(2)} MB</td><td className="time-cell">{formatTime(capture.created_at)}</td></tr>)}</tbody></table></div>}</section>}
        {showUploader && <form className="upload-panel" onSubmit={handleUpload}><div><span className="eyebrow">INGEST CAPTURE</span><h2>Analyze a new PCAP</h2><p>Maximum 50 MB. The frontend now uses <code>{API_BASE_URL || "same-origin"}</code> as its API base. {jobStatus ? `JOB ${jobStatus.toUpperCase()} · ${jobProgress}%` : "Analysis runs in the background."}</p></div><label className="file-drop"><HardDrive size={19}/><span>{file ? file.name : "Choose a .pcap file"}</span><small>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : "PCAP only / 50 MB max"}</small><input type="file" accept=".pcap,.pcapng" onChange={(event) => setFile(event.target.files?.[0] ?? null)}/></label><button className="primary-button" disabled={!file || loading}>{loading ? <><LoaderCircle size={15} className="spin"/> ANALYZING</> : "RUN ANALYSIS"}</button></form>}
        <section className="metric-grid"><Metric icon={<Activity size={14}/>} label="PARSED FLOWS" value={results?.parsed_flows ?? 0} detail={`${results?.total_packets?.toLocaleString() ?? 0} packets inspected`} accent="#00dbe9"/><Metric icon={<AlertOctagon size={14}/>} label="ACTIVE FINDINGS" value={findings.length} detail={`${highRisk} P0/P1 high-risk signals`} accent="#ff7167"/><Metric icon={<Shield size={14}/>} label="AVG RISK SCORE" value={avgRisk} detail="bounded 0–100 model" accent="#ffb45f"/><Metric icon={<Server size={14}/>} label="UNSUPPORTED PKTS" value={results?.unsupported_packets ?? 0} detail="parser skips / review" accent="#9ca6b6"/></section>
        <section className="content-grid"><div className="panel timeline-panel" id="timeline"><div className="panel-heading"><div><span className="eyebrow">SIGNAL HISTORY</span><h2>Findings over time</h2></div><span className="panel-tag">{timeline.length ? `${timeline.length} BUCKETS` : "NO DATA"}</span></div><div className="timeline-chart" role="img" aria-label="Findings over time chart">{timeline.length ? <ResponsiveContainer width="100%" height={255}><AreaChart data={timeline} margin={{ top: 18, right: 12, left: -22, bottom: 0 }}><defs><linearGradient id="timelineFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#00dbe9" stopOpacity={0.34}/><stop offset="100%" stopColor="#00dbe9" stopOpacity={0.02}/></linearGradient></defs><CartesianGrid stroke="#29333e" vertical={false}/><XAxis dataKey="label" tick={{ fill: "#8290a0", fontSize: 10, fontFamily: "IBM Plex Mono" }} axisLine={false} tickLine={false}/><YAxis allowDecimals={false} tick={{ fill: "#8290a0", fontSize: 10, fontFamily: "IBM Plex Mono" }} axisLine={false} tickLine={false}/><Tooltip contentStyle={{ background: "#151b20", border: "1px solid #36434f", color: "#e6edf3", fontFamily: "IBM Plex Mono", fontSize: 11 }} labelStyle={{ color: "#00dbe9" }}/><Area type="monotone" dataKey="findings" name="Findings" stroke="#00dbe9" strokeWidth={2} fill="url(#timelineFill)"/><Area type="monotone" dataKey="highRisk" name="P0/P1" stroke="#ff7167" strokeWidth={2} fill="none"/></AreaChart></ResponsiveContainer> : <div className="empty-state">No findings match this severity filter.</div>}</div><div className="chart-legend"><span><i className="legend-cyan"/> ALL FINDINGS</span><span><i className="legend-red"/> P0 / P1</span><span className="legend-note">Buckets are derived from finding timestamps returned by the API.</span></div></div><div className="panel distribution-panel"><div className="panel-heading"><div><span className="eyebrow">SEVERITY DISTRIBUTION</span><h2>Risk by tier</h2></div><span className="panel-tag">{findings.length} TOTAL</span></div><div className="severity-bars">{severityOrder.map((level) => { const count = findings.filter((finding) => finding.tier === level).length; const width = findings.length ? Math.max(3, count / findings.length * 100) : 3; return <button key={level} className="severity-bar-row" onClick={() => setSeverity(level)}><span className={severityClass(level)}>{level}</span><div className="bar-track"><i style={{ width: `${width}%`, background: severityColors[level] }}/></div><b>{count}</b></button>; })}</div><div className="distribution-note"><AlertTriangle size={15}/> Click a tier to filter the evidence log below.</div></div></section>
        <section className="panel findings-panel" id="findings"><div className="panel-heading findings-heading"><div><span className="eyebrow">EVIDENCE LOG</span><h2>Suspicious activity</h2></div><div className="finding-tools"><div className="search-box"><Search size={14}/><input aria-label="Filter findings by IP address or title" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="FILTER IP / TITLE"/></div><div className="filter-group"><Filter size={14}/>{severityLabels.map((level) => <button key={level} className={severity === level ? "filter-button active" : "filter-button"} aria-pressed={severity === level} onClick={() => setSeverity(level)}>{level}</button>)}</div><button className="outline-button small" onClick={() => exportFindings(filteredFindings)}><Download size={14}/> CSV</button></div></div><div className="findings-table-wrap"><table className="findings-table"><thead><tr><th>SEVERITY</th><th>SOURCE IP</th><th>PRIMARY INDICATOR</th><th>RISK</th><th>LAST ACTIVE</th><th> </th></tr></thead><tbody>{filteredFindings.map((finding) => <tr key={finding.id} className={selected?.id === finding.id ? "row-selected" : ""} tabIndex={0} aria-selected={selected?.id === finding.id} onClick={() => setSelected(finding)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelected(finding); } }}><td><span className={severityClass(finding.tier)}>{finding.tier}</span></td><td className="ip-cell">{finding.source_ip}</td><td><strong>{finding.title}</strong><small>{finding.contributing_signals[0] ?? "NO SIGNAL LABEL"}</small></td><td><div className="risk-cell"><div><i style={{ width: `${Math.max(4, Math.min(100, finding.risk_score))}%`, background: severityColors[finding.tier] }}/></div><b>{finding.risk_score}</b></div></td><td className="time-cell">{formatTime(finding.last_seen)}</td><td><ChevronRight size={16}/></td></tr>)}</tbody></table>{filteredFindings.length === 0 && <div className="empty-state table-empty">No findings match the current filters.</div>}</div></section>
        <section className="investigation-panel" id="investigation">{selected ? <><div className="investigation-head"><div><span className="eyebrow">SELECTED FINDING / {selected.id}</span><h2>{selected.title}</h2></div><div className={severityClass(selected.tier)}>{selected.tier} / {selected.risk_score}</div></div><div className="investigation-grid"><div><span className="detail-label">SOURCE HOST</span><strong className="detail-value cyan">{selected.source_ip}</strong></div><div><span className="detail-label">DESTINATION</span><strong className="detail-value">{selected.dest_ip}:{selected.dest_port ?? "—"}</strong></div><div><span className="detail-label">OBSERVED WINDOW</span><strong className="detail-value">{formatTime(selected.first_seen)} → {formatTime(selected.last_seen)}</strong></div><div><span className="detail-label">SIGNALS</span><div className="signal-pills">{selected.contributing_signals.map((signal) => <span key={signal}>{signal}</span>)}</div></div><div><span className="detail-label">DETECTOR CONFIDENCE</span><strong className="detail-value">{selected.confidence !== undefined ? `${Math.round(selected.confidence * 100)}% evidence strength` : "Not reported"}</strong><small>{selected.detector_id ?? "unknown detector"} · {selected.detector_version ?? "unversioned"}</small></div></div><div className="evidence-row"><div><span className="detail-label">SECURITY EVIDENCE</span>{selected.evidence.map((item) => <p key={item}><Check size={13}/>{item}</p>)}</div><button className="outline-button" onClick={() => exportFindingsJson([selected])}><Download size={14}/> EXPORT JSON</button><button className="outline-button" onClick={() => exportFindings([selected])}><Download size={14}/> EXPORT CSV</button></div><div className="explanation-panel"><div><span className="detail-label">WHY THIS WAS FLAGGED</span>{(selected.explanation ?? []).map((item) => <p key={item}>{item}</p>)}{!selected.explanation?.length && <p>No explanation metadata was returned by the connected API.</p>}</div><div><span className="detail-label">CALIBRATION</span><strong className="detail-value">{selected.calibrated_probability !== undefined ? `${Math.round(selected.calibrated_probability * 100)}% estimated probability` : "Raw score only"}</strong><small>{selected.calibration_method ?? "raw-score-fallback"}</small></div></div></> : <div className="empty-state">Select a finding to open the investigation view.</div>}</section>
      </main></div>
  </div>;
}
