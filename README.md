# FlowCrypid

## Threat-intelligence dashboard for network-flow investigation

FlowCrypid is a cybersecurity dashboard prototype designed to help analysts inspect behavioral anomalies and potential low-and-slow data exfiltration in network captures. The project presents suspicious activity through a focused security-operations-console interface with severity tiers, bounded risk scores, temporal context, evidence details, and exportable findings.

> **Submission scope:** This archive contains the upgraded React/Vite dashboard, typed API integration layer, a working FastAPI PCAP-analysis backend, demo data, and reproducible Docker deployment templates. When no API is available, the dashboard intentionally starts in clearly labeled **DEMO MODE** so the interface can still be reviewed.

## Project highlights

The upgraded interface is built around an analyst workflow rather than a generic metrics page. It includes an overview of parsed flows and active findings, a severity distribution, a findings-over-time chart, searchable evidence, severity filters, CSV export, PCAP upload controls, and a selected-finding investigation panel.

The frontend uses typed response contracts for health checks, asynchronous jobs, and PCAP-analysis results. It accepts findings from an API while normalizing incomplete responses into a predictable display shape. Findings now include a versioned `FLOW-ENSEMBLE` detector identity, evidence-strength confidence, independent contributing signals, and explanations that explicitly distinguish operational risk from calibrated probability. The API base URL is configurable through `VITE_API_BASE_URL`; an empty value uses same-origin `/api/*` paths, which is suitable for the included Nginx reverse-proxy configuration.

| Capability | Description |
|---|---|
| Security overview | Parsed flows, packet counts, active findings, average risk, and unsupported packets. |
| Severity model | P0–P5 presentation with distinct visual treatment and filter controls. |
| Temporal analysis | Findings are grouped into hourly timeline buckets using returned timestamps. |
| Evidence investigation | Analysts can select a finding and inspect source, destination, observed window, signals, evidence, detector version, confidence, and explanation. |
| Search and filtering | Findings can be filtered by severity and searched by source IP, destination IP, or title. |
| Export | Visible findings or a selected finding can be downloaded as CSV or structured JSON, including detector provenance and confidence metadata. |
| PCAP ingestion | The UI accepts `.pcap` and `.pcapng` files, submits a background analysis job, polls its status, and displays the completed result. |
| Protected workflow | Login, bearer sessions, analyst/admin role checks, logout, authorized capture history, and authenticated job polling. |
| Durable local storage | SQLite stores users, sessions, capture metadata, and findings in the mounted `storage/` directory. |
| Upload security | Server-side extension, size, packet-count, empty-file, and malformed-capture validation. |
| Demo fallback | A static, labeled demo snapshot keeps the product experience reviewable without a connected backend. |

## Technology

The submission uses React 19, TypeScript, Vite, Recharts, Lucide icons, FastAPI, Scapy, SQLite, and a small Express serving entrypoint. The project is managed with pnpm and includes Docker/Nginx deployment templates for the frontend and backend.

## Getting started

### Prerequisites

Use Node.js 22 or a compatible current Node.js release, pnpm 10, and a modern browser. The commands below are intended for local review from the repository root.

### Install dependencies

```bash
pnpm install --frozen-lockfile
```

### Run the development dashboard

```bash
pnpm dev
```

Vite will print the local URL in the terminal. With no backend configured, the dashboard displays its labeled demo snapshot and reports **DEMO MODE** for the API status.

### Run against a separate API

If the FlowCrypid FastAPI service is running on port 8000, start the frontend with:

```bash
VITE_API_BASE_URL=http://localhost:8000 pnpm dev
```

For a deployed API, set the variable to its HTTPS origin at build time:

```bash
VITE_API_BASE_URL=https://api.example.com pnpm build
```

The frontend calls `GET /api/health` for service status, `POST /api/auth/login` for a bearer session, `POST /api/upload` with an authenticated multipart field named `file` to queue protected PCAP ingestion, `GET /api/jobs/{job_id}` to poll analysis status, and `GET /api/captures` to load authorized capture history. The expected response shapes are defined in `client/src/lib/flowcrypid.ts`. Configure the initial administrator through `FLOWCRYPID_ADMIN_EMAIL` and `FLOWCRYPID_ADMIN_PASSWORD`; there are no built-in production credentials, and the password must be at least 12 characters.

### Verify the submission

```bash
pnpm check
pnpm build
pnpm test:backend
```

`pnpm check` runs the TypeScript compiler without emitting files. `pnpm build` creates the Vite production output and bundles the included server entrypoint. `pnpm test:backend` runs the secure backend smoke test and the complete `pytest` regression suite. Together they verify authentication, authorization, protected upload handling, persistence, invalid-file rejection, session revocation, parser behavior, detector boundaries, feature extraction, risk scoring, and threat-intelligence fallback behavior.

## Persisted Isolation Forest ML pipeline

The backend now runs a real persisted unsupervised ML stage for every parsed flow:

> PCAP → Flow → canonical feature vector → `RobustScaler` → `IsolationForest` → anomaly score

The artifacts load at application startup from `models/isolation_forest.joblib` and `models/scaler.joblib`. Rebuild them with:

```bash
PYTHONPATH=. python3 scripts/train_isolation_forest.py --input evaluation/data/iforest_training.csv
```

The trainer uses only benign rows from the `train` split because Isolation Forest learns normal traffic. The checked-in CSV is a small local development baseline; production deployments should replace it with an authorized, documented benign flow extract using the same feature columns. The detector status endpoint reports artifact readiness, and anomalous flows are returned with detector ID `ML-ISOLATION-FOREST`, raw decision-function evidence, and a normalized score from 0 to 1.

## Evaluation and explainability

The `evaluation/` directory contains the canonical input schema and reproducible benchmark runner. The recommended source is the official [CIC-IDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html); the repository does not redistribute its records. Convert an authorized dataset extract to the documented canonical CSV format and run:

```bash
python3 scripts/evaluate_detectors.py \\
  --input evaluation/data/cicids2017_canonical.csv \\
  --split test \\
  --output evaluation/results/test_metrics.json
```

The runner reports overall and detector-level accuracy, precision, recall, F1, false-positive rate, false-negative rate, confusion-matrix counts, and score distribution. It can also fit a Platt calibration file from a labeled training split. Findings returned by the API include the detector explanation, raw risk score, calibration method, and calibrated probability when a calibration file is configured. Without a fitted calibration file, the API explicitly reports `raw-score-fallback` rather than presenting an unvalidated score as a probability.

## Measured benchmark

A reproducible benchmark was run against the published UNSW-NB15 training CSV. Because the accessible training and testing copies were byte-identical, the project does not claim an official UNSW train/test result; the runner instead uses a disjoint deterministic `id % 10` holdout. The evaluation contains 3,500 benign and 3,500 malicious flows, with 33,301 benign flows used for fitting.

| Metric | Measured value |
|---|---:|
| Accuracy | 51.8429% |
| Precision | 63.4096% |
| Recall | 8.7143% |
| F1 | 15.3228% |
| FPR | 5.0286% |
| FNR | 91.2857% |

The full confusion matrix, SHA-256 provenance, feature mapping, model configuration, and limitations are in `evaluation/results/unsw_nb15_benchmark.md` and `evaluation/results/unsw_nb15_benchmark.json`. These are measured results, not performance claims for production traffic.

## Configuration

The browser-side upload panel applies a 50 MB usability check before sending a file. The API independently enforces the same size limit, packet-count limits, extension and PCAP magic-byte validation, empty-file handling, malformed-capture handling, temporary-file cleanup, authentication, role authorization, and upload rate limits. Login attempts and uploads are throttled per client address. Configure the initial administrator through environment variables before enabling authenticated workflows.

| Variable | Purpose | Default |
|---|---|---|
| `VITE_API_BASE_URL` | API origin used for health and upload requests. | Empty, meaning same-origin `/api/*` paths. |
| `FLOWCRYPID_CALIBRATION_PATH` | Optional fitted Platt calibration JSON path. | `models/calibration.json` |
| `FLOWCRYPID_MAX_PACKETS` | Maximum packets processed per capture and benchmark safety bound. | `500000` |
| `FLOWCRYPID_RETENTION_DAYS` | Capture retention period used during startup cleanup. | `30` |
| `FLOWCRYPID_PRIVACY_MODE` | Set to `redact` to anonymize IPs in returned findings. | `off` |
| `FLOWCRYPID_LOG_LEVEL` | Structured API log level. | `INFO` |
| `FLOWCRYPID_WORKER_COUNT` | Number of in-process background analysis workers. | `2` |

## Deployment notes

The frontend container uses `deployments/docker/Dockerfile.frontend` and serves the compiled Vite output through Nginx. The included `nginx.conf` proxies `/api/*` to a service named `backend` and sets a 50 MB request limit. The backend exposes `/api/health/live`, `/api/health/ready`, and `/api/metrics` for operational checks and monitoring.

The backend container is built from the included `requirements.txt`, `apps/`, and `models/` paths. `docker-compose.yml` starts the FastAPI service, whose in-process worker pool handles queued analysis jobs, waits for its health check, and serves the frontend through Nginx at `http://localhost:8080`. The current worker pool is intentionally local to one backend process; a later production deployment should move it to a separate durable queue worker.

## Operations, backups, and privacy

The operational runbooks are in `runbooks/OPERATIONS.md` and `runbooks/PRIVACY.md`. Create and verify a SQLite backup with `python3 scripts/backup_restore.py backup`; restore to a new path with the `restore` subcommand and never overwrite the live database during an incident. The CI workflow runs frontend and backend checks, dependency audits, and secret scanning. The application supports configurable retention and an explicit privacy redaction mode, but backups and production storage still require encryption and access controls outside this repository.

## Submission limitations

FlowCrypid is a **student-level threat-intelligence prototype** with a working local parser and rule-based analysis path. The included demo findings and lightweight heuristics do not establish detector precision, recall, false-positive rate, robustness, or generalization to real enterprise traffic. Those claims require a larger documented dataset, reproducible experiments, detector-level tests, and calibrated model evaluation.

The current submission now demonstrates server-side authentication, role checks, upload enforcement, SQLite persistence, session revocation, rate limiting, asynchronous in-process analysis jobs, versioned multi-signal findings, and persisted Isolation Forest inference with explicit score evidence. It still does not provide password-reset flows, an external identity provider, persistent audit logging, a shared rate-limit store, a separate durable queue worker, calibrated machine-learning probabilities, multi-tenant isolation, or production monitoring. These remain appropriate next steps before handling sensitive enterprise data.

## Suggested review path

A reviewer can begin with `pnpm install --frozen-lockfile`, run `pnpm dev`, and inspect the dashboard in demo mode. The recommended interaction path is to review the overview metrics, click severity tiers, search the evidence table, select a finding, inspect its signals, evidence, explanation, and calibration status, export the current findings as CSV, and open the PCAP ingestion panel. Keyboard users can use the skip link, tab through controls, and press Enter or Space on a finding row.

## Repository map

| Path | Purpose |
|---|---|
| `client/src/App.tsx` | Main security dashboard, demo state, API workflow, filters, timeline, and export logic. |
| `client/src/lib/api.ts` | Runtime API URL resolution, authentication, session, and upload requests. |
| `client/src/lib/flowcrypid.ts` | Typed API contracts, finding normalization, severity helpers, and timestamp formatting. |
| `client/src/index.css` | Dashboard layout, visual system, responsive behavior, accessibility focus states, and component styling. |
| `server/index.ts` | Included static-serving/server entrypoint. |
| `deployments/docker/` | Frontend/backend container definitions plus Nginx configuration. |
| `apps/api/main.py` | FastAPI authentication, authorization, upload security, SQLite persistence, PCAP parsing, flow aggregation, and heuristic findings. |
| `requirements.txt` | Pinned Python backend dependencies. |
| `docker-compose.yml` | Reproducible local frontend/backend deployment with persistent SQLite storage. |
| `client/API_CONFIGURATION.md` | API configuration details and deployment guidance. |
| `evaluation/README.md` | Dataset provenance, canonical schema, split guidance, and benchmark commands. |
| `scripts/evaluate_detectors.py` | Reproducible overall and detector-level metrics runner. |
| `apps/api/calibration.py` | Platt calibration utilities and calibrated-probability fallback behavior. |
| `runbooks/OPERATIONS.md` | Health checks, backup/restore, incident response, and operations procedures. |
| `runbooks/PRIVACY.md` | Sensitive-PCAP handling, redaction, retention, sharing, and deletion guidance. |
| `.github/workflows/ci.yml` | Frontend/backend CI, dependency audits, and secret scanning. |
| `scripts/backup_restore.py` | SQLite backup, checksum, integrity-check, and restore utility. |
| `audit-report.md` | Current honest assessment of strengths, limitations, and recommended next steps. |

## License

This project is distributed under the MIT License as declared in `package.json`.
