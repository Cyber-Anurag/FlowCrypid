// Signal Ledger design: forensic editorial audit, warm ivory/ink black, signal orange, acid chartreuse; evidence-first interactions.
import { useEffect, useMemo, useRef, useState } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ArrowUpRight, Bookmark, Check, ChevronDown, Copy, FileText, Github, Menu, RefreshCw, Share2, ShieldAlert, TriangleAlert, Upload, X } from "lucide-react";

const scoreData = [
  { subject: "Concept", score: 12, fullMark: 15 },
  { subject: "Architecture", score: 9, fullMark: 15 },
  { subject: "Detection rigor", score: 8, fullMark: 20 },
  { subject: "Evaluation", score: 6, fullMark: 15 },
  { subject: "Engineering", score: 7, fullMark: 15 },
  { subject: "UX", score: 5, fullMark: 10 },
  { subject: "Documentation", score: 7, fullMark: 10 },
];
const bars = scoreData.map((d) => ({ name: d.subject, earned: d.score, possible: d.fullMark }));
const severityData = [
  { label: "Evidence gaps", value: 31 },
  { label: "Production blockers", value: 25 },
  { label: "UX friction", value: 19 },
  { label: "Academic risk", value: 16 },
  { label: "Good foundation", value: 9 },
];
const findings = [
  { id: "F-01", tag: "BLOCKER", title: "The frontend is hard-wired to localhost", text: "Both the health check and upload request target http://localhost:8000. A deployed frontend cannot reach a user’s machine at that address, so the headline workflow breaks outside the author’s laptop.", evidence: "src/src/App.tsx:12, 29", category: "Production", tone: "red" },
  { id: "F-02", tag: "WEAK PROOF", title: "The model is trained on synthetic benign data", text: "The training script creates 5,000 random-looking flows and records synthetic_benign in model metadata. That is acceptable for a prototype demo, but it cannot establish real-world precision, recall, false-positive rate, or robustness.", evidence: "evaluation/train_model.py:9–54; models/model_metadata.json", category: "Evidence", tone: "orange" },
  { id: "F-03", tag: "CLAIM / TEST GAP", title: "The README promises P0–P5, but test coverage is narrow", text: "The repository describes six detectors, while the visible tests directly exercise risk bounds, temporal aggregation, and P1 rare destinations. There is no evidence here of systematic tests for DNS tunneling, staging, or multi-stage correlation.", evidence: "README.md:13–20; tests/*.py", category: "Evidence", tone: "orange" },
  { id: "F-04", tag: "DEPLOYMENT", title: "docker-compose references files absent from the submission", text: "The compose file points at deployments/docker/Dockerfile.backend and Dockerfile.frontend. Those paths were not present in the submitted project listing, making the advertised Docker path non-reproducible as delivered.", evidence: "docker-compose.yml:5–17; submitted file inventory", category: "Engineering", tone: "red" },
  { id: "F-05", tag: "SECURITY", title: "The upload boundary is stronger in the UI than in the API", text: "The client checks a 50 MB limit, but the API code shown does not establish an equivalent server-side size guard, authentication, rate limiting, or durable audit trail. Client-only limits are easy to bypass.", evidence: "src/src/App.tsx:20–22; apps/api/main.py", category: "Security", tone: "red" },
  { id: "F-06", tag: "UX", title: "The dashboard is a demo surface, not an analyst workflow", text: "The interface exposes a table and an IP panel, but no filtering, sorting, time context, export, pagination, keyboard affordance, empty-state explanation, or visual trend view. The use of alert() and an unlabelled “x” also reads as unfinished.", evidence: "src/src/App.tsx:68–191", category: "UX", tone: "orange" },
  { id: "F-07", tag: "GOOD START", title: "The detector has a coherent prototype spine", text: "PCAP parsing, feature extraction, baseline comparison, bounded risk scoring, a FastAPI endpoint, and a React surface form a credible end-to-end teaching artifact. The problem choice is stronger than the proof currently attached to it.", evidence: "README.md:8–11; apps/*; src/src/App.tsx", category: "Foundation", tone: "green" },
];

function SectionLabel({ children }: { children: React.ReactNode }) { return <div className="section-label"><span className="section-dot" />{children}</div>; }

export default function Home() {
  const [filter, setFilter] = useState("All findings");
  const [open, setOpen] = useState<string | null>("F-01");
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [liveFindings, setLiveFindings] = useState<any[]>([]);
  const [liveStatus, setLiveStatus] = useState("Not connected");
  const [liveError, setLiveError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const refreshLiveFindings = async () => {
    setLiveStatus("Loading…");
    setLiveError("");
    try {
      const response = await fetch("/api/captures?limit=10", { credentials: "include" });
      if (!response.ok) throw new Error(response.status === 401 ? "Sign in to view live captures." : `API returned ${response.status}.`);
      const captures = await response.json();
      setLiveFindings(captures.flatMap((capture: any) => capture.findings || []).slice(0, 10));
      setLiveStatus("Live");
    } catch (error) {
      setLiveStatus("Unavailable");
      setLiveError(error instanceof Error ? error.message : "Could not reach the API.");
    }
  };
  const uploadLiveCapture = async (file: File) => {
    setLiveStatus("Uploading…");
    setLiveError("");
    const body = new FormData(); body.append("file", file);
    try {
      const response = await fetch("/api/upload", { method: "POST", body, credentials: "include" });
      if (!response.ok) throw new Error(response.status === 401 ? "Sign in before uploading a capture." : `Upload failed (${response.status}).`);
      setLiveStatus("Queued");
      window.setTimeout(refreshLiveFindings, 1200);
    } catch (error) {
      setLiveStatus("Unavailable");
      setLiveError(error instanceof Error ? error.message : "Upload failed.");
    }
  };
  useEffect(() => { refreshLiveFindings(); }, []);
  const filtered = useMemo(() => filter === "All findings" ? findings : findings.filter((f) => f.category === filter), [filter]);
  const share = async () => {
    const url = window.location.href;
    try { await navigator.clipboard.writeText(url); setCopied(true); setTimeout(() => setCopied(false), 1600); } catch { window.prompt("Copy report URL", url); }
  };
  return <div className="report-shell">
    <aside className="rail">
      <div className="brand"><div className="brand-mark" aria-hidden="true">FL</div><div><strong>FLOWCRYPID</strong><span>BRUTAL AUDIT / 01</span></div></div>
      <div className="rail-rule" />
      <nav><a className="active" href="#verdict">01 / Verdict</a><a href="#live">02 / Live console</a><a href="#score">03 / Scorecard</a><a href="#evidence">03 / Evidence</a><a href="#roadmap">04 / Roadmap</a></nav>
      <div className="rail-note"><span>REVIEW BASIS</span><p>Static inspection of the submitted ZIP, source files, tests, model metadata, README, and compose configuration.</p></div>
      <div className="rail-bottom"><span>REVIEWED</span><strong>30 AUG 2026</strong><span>MODE</span><strong>NO-MERCY / CONSTRUCTIVE</strong></div>
    </aside>
    <main className="main-canvas">
      <header className="topbar"><div className="crumb"><FileText size={15}/> COLLEGE PROJECT REVIEW <span>/</span> FLOWCRYPID</div><div className="top-actions"><button onClick={() => { setSaved(!saved); }} className={saved ? "action active-action" : "action"}><Bookmark size={15} fill={saved ? "currentColor" : "none"}/>{saved ? "Saved" : "Save"}</button><button onClick={share} className="action"><Share2 size={15}/>{copied ? "Copied" : "Share"}</button><button className="mobile-menu" onClick={() => setMenuOpen(!menuOpen)} aria-label="Toggle menu">{menuOpen ? <X size={18}/> : <Menu size={18}/>}</button></div></header>
      <section id="verdict" className="hero-section">
        <div className="hero-copy"><SectionLabel>THE VERDICT</SectionLabel><h1>The idea is stronger<br/><em>than the proof.</em></h1><p className="dek">FlowCrypid is a credible security prototype with a sensible end-to-end spine. But right now it demonstrates a controlled story, not a defensible detection system.</p><div className="hero-meta"><span><b>52</b> / 100</span><span className="meta-line"/><span>STRICT COLLEGE STANDARD</span></div></div>
        <div className="hero-score"><div className="score-kicker">OVERALL SCORE</div><div className="score-number">52</div><div className="score-denom">out of 100</div><div className="score-bar"><i style={{width: "52%"}} /></div><div className="score-foot"><span>PASSABLE PROTOTYPE</span><span>NOT YET PORTFOLIO-READY</span></div></div>
      </section>
      <section className="signal-strip"><div><span className="signal-index">01</span><strong>BEST ASSET</strong><p>Clear problem framing around low-and-slow exfiltration.</p></div><div><span className="signal-index orange">02</span><strong>BIGGEST LIABILITY</strong><p>Evaluation is synthetic and the deployment path is broken.</p></div><div><span className="signal-index red">03</span><strong>DO THIS FIRST</strong><p>Make the experiment reproducible before adding more detectors.</p></div></section>
      <section id="live" className="section-block live-console"><div className="section-heading"><div><SectionLabel>LIVE ANALYST CONSOLE</SectionLabel><h2>Findings from the running API.</h2></div><div className="live-actions"><span className={`live-status ${liveStatus.toLowerCase()}`}>{liveStatus}</span><button className="action" onClick={refreshLiveFindings}><RefreshCw size={15}/> Refresh</button><button className="action" onClick={() => fileInput.current?.click()}><Upload size={15}/> Upload PCAP</button><input ref={fileInput} type="file" accept=".pcap,.pcapng" hidden onChange={(event) => { const file = event.target.files?.[0]; if (file) uploadLiveCapture(file); event.currentTarget.value = ""; }} /></div></div>{liveError && <p className="live-error">{liveError}</p>}<div className="live-findings">{liveFindings.length ? liveFindings.map((finding: any) => <article className="live-finding" key={finding.id}><span>{finding.tier || "P?"}</span><strong>{finding.title}</strong><b>{finding.risk_score ?? "—"}/100</b><small>{finding.source_ip} → {finding.dest_ip}:{finding.dest_port}</small></article>) : <p className="live-empty">No live findings returned. Sign in, upload <code>demo/sample.pcap</code>, and refresh to see the API result here.</p>}</div></section>
      <section id="score" className="section-block"><div className="section-heading"><div><SectionLabel>THE SCORECARD</SectionLabel><h2>Where the points went.</h2></div><p>Scores reward demonstrated quality, not ambition. A well-written README cannot substitute for tests, measurements, or a working deployment path.</p></div><div className="score-layout"><div className="chart-panel radar-panel"><div className="panel-head"><span>Capability shape</span><span className="mono">MAX / CATEGORY</span></div><ResponsiveContainer width="100%" height={340}><RadarChart cx="50%" cy="50%" outerRadius="72%" data={scoreData}><PolarGrid stroke="#c8c1b4"/><PolarAngleAxis dataKey="subject" tick={{ fill: "#3a3935", fontSize: 11, fontFamily: "IBM Plex Mono" }}/><Radar name="earned" dataKey="score" stroke="#f26b38" fill="#f26b38" fillOpacity={0.28} strokeWidth={2}/><Tooltip contentStyle={{background:"#171716", border:"none", color:"#fff", fontFamily:"IBM Plex Mono", fontSize:12}} /></RadarChart></ResponsiveContainer></div><div className="chart-panel"><div className="panel-head"><span>Earned vs possible</span><span className="mono">POINTS</span></div><ResponsiveContainer width="100%" height={340}><BarChart data={bars} layout="vertical" margin={{left: 8, right: 18, top: 10, bottom: 4}}><CartesianGrid horizontal={false} stroke="#ded7cb"/><XAxis type="number" domain={[0,20]} hide/><YAxis type="category" dataKey="name" width={100} tick={{fill:"#3a3935", fontSize:11, fontFamily:"IBM Plex Mono"}}/><Bar dataKey="possible" fill="#ded7cb" barSize={18} radius={[0,2,2,0]}><Cell fill="#ded7cb"/></Bar><Bar dataKey="earned" fill="#f26b38" barSize={18} radius={[0,2,2,0]}/><Tooltip cursor={{fill:"#f7f3eb"}} contentStyle={{background:"#171716", border:"none", color:"#fff", fontFamily:"IBM Plex Mono", fontSize:12}} /></BarChart></ResponsiveContainer><div className="chart-legend"><span><i className="legend-orange"/> earned</span><span><i className="legend-grey"/> available</span></div></div></div></section>
      <section className="section-block exhibit"><div className="exhibit-copy"><SectionLabel>THE PATTERN</SectionLabel><h2>Most of the lost score is not “more features.”</h2><p>The failure pattern is evidence debt: the project keeps making claims faster than it creates repeatable proof. That is fixable, but it changes the next semester of work.</p><div className="annotation">// SIGNAL DENSITY / RISK CONCENTRATION</div></div><div className="chart-panel pattern-chart"><ResponsiveContainer width="100%" height={230}><AreaChart data={[{x:"concept",y:12},{x:"architecture",y:21},{x:"detection",y:29},{x:"evaluation",y:35},{x:"engineering",y:42},{x:"UX",y:47},{x:"docs",y:52}]}><defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#b7d93c" stopOpacity={0.55}/><stop offset="100%" stopColor="#b7d93c" stopOpacity={0.03}/></linearGradient></defs><CartesianGrid stroke="#ded7cb" vertical={false}/><XAxis dataKey="x" tick={{fill:"#817b70",fontSize:10,fontFamily:"IBM Plex Mono"}} axisLine={false} tickLine={false}/><YAxis hide domain={[0,60]}/><Area type="monotone" dataKey="y" stroke="#7a9320" strokeWidth={3} fill="url(#fill)"/><Tooltip contentStyle={{background:"#171716", border:"none", color:"#fff", fontFamily:"IBM Plex Mono", fontSize:12}} /></AreaChart></ResponsiveContainer><div className="pattern-caption"><span>score accumulation</span><span>evidence debt accelerates after the detector layer</span></div></div></section>
      <section id="evidence" className="section-block evidence-section"><div className="section-heading"><div><SectionLabel>THE EVIDENCE LOG</SectionLabel><h2>What is holding it back.</h2></div><div className="filter-row">{["All findings","Production","Evidence","Security","UX","Engineering","Foundation"].map((item) => <button key={item} className={filter === item ? "filter active-filter" : "filter"} onClick={() => setFilter(item)}>{item}</button>)}</div></div><div className="finding-list">{filtered.map((f) => <article key={f.id} className={`finding ${open === f.id ? "finding-open" : ""}`}><button className="finding-trigger" onClick={() => setOpen(open === f.id ? null : f.id)}><span className="finding-id">{f.id}</span><span className={`tag ${f.tone}`}>{f.tag}</span><strong>{f.title}</strong><ChevronDown size={18} className="chevron" /></button>{open === f.id && <div className="finding-detail"><p>{f.text}</p><span className="evidence-ref">{f.evidence}</span></div>}</article>)}</div></section>
      <section id="roadmap" className="roadmap-section"><div className="roadmap-intro"><SectionLabel>THE RECOVERY PLAN</SectionLabel><h2>Make it defensible in four moves.</h2><p>Do not add P6. Tighten the loop that turns a claim into a measurable result.</p></div><div className="roadmap-grid"><div><span>01</span><h3>Fix the run path</h3><p>Use an environment-based API URL, add the missing Dockerfiles, and document one clean setup command.</p></div><div><span>02</span><h3>Build a real corpus</h3><p>Collect or cite public PCAP sources, separate train/validation/test periods, and record labels and class balance.</p></div><div><span>03</span><h3>Measure honestly</h3><p>Report precision, recall, F1, false-positive rate, confusion matrices, and detector-level ablations.</p></div><div><span>04</span><h3>Upgrade analyst UX</h3><p>Add filters, time context, export, accessible status messaging, and an explanation view for each signal.</p></div></div><div className="finish-line"><TriangleAlert size={17}/><strong>Target after revision: 78 / 100</strong><span>if the evidence catches up to the architecture</span><ArrowUpRight size={17}/></div></section>
      <footer><div><span className="footer-mark">FL / 01</span><p>Prepared as a direct project review.<br/>The score is a snapshot, not a verdict on the person.</p></div><div className="footer-actions"><button onClick={() => window.print()}><FileText size={15}/> Print / save PDF</button><button onClick={share}><Copy size={15}/> {copied ? "Link copied" : "Copy report link"}</button><a href="https://github.com" target="_blank" rel="noreferrer"><Github size={15}/> Project reference <ArrowUpRight size={14}/></a></div></footer>
    </main>
  </div>;
}
