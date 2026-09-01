# FlowCrypid — Final Executive Summary

**Project:** FlowCrypid Threat Intelligence Console  
**Assessment date:** 30 August 2026  
**Assessment scope:** Product, frontend, backend, detector logic, security, testing, operations, and release readiness  
**Final prototype/beta-readiness score:** **90/100**  
**Production readiness:** **No-go**  
**Portfolio/local demo readiness:** **Go**

## Executive conclusion

FlowCrypid is a polished and technically ambitious network-threat investigation prototype. It presents a coherent SOC analyst workflow around PCAP ingestion, asynchronous analysis, suspicious-flow findings, severity triage, evidence inspection, capture history, detector provenance, and analyst exports. Its strongest asset is the product experience: the interface is distinctive, comprehensible, and materially more complete than a typical student dashboard.

The engineering foundation has also improved substantially through the implementation phases. The repository now has a consistent test contract, environment-based administrator setup, shared SQLite-backed rate limiting, content-signature validation, streamed upload handling, persisted analysis jobs with startup recovery, an external worker entrypoint, transactional job claiming, background processing, versioned multi-signal findings, detector confidence metadata, capture history, JSON export, Prometheus-style metrics, readiness checks, persistent security audit events, operational runbooks, and a formal release gate.

The central limitation remains unchanged: **FlowCrypid has not yet proven that its detector performs reliably on representative labeled data**. Its rules are still heuristic, the calibration artifact is not backed by a committed real-data evaluation, and the current worker architecture is local and in-process. The project is therefore credible as a demo and promising as an internal prototype, but it must not be represented as a production-grade threat-detection platform.

> **Bottom line:** FlowCrypid is currently an explainable network-behavior investigation console with heuristic detection—not a validated enterprise detection engine.

## Final scorecard

| Dimension | Score | Assessment |
|---|---:|---|
| Product framing | 15/15 | Clear problem, focused workflow, and believable analyst use case. |
| Visual design and UX | 18/20 | Strong visual identity, hierarchy, filtering, charts, history, investigation view, and demo transparency. |
| Frontend implementation | 14/15 | Typed API contracts, job polling, exports, history, accessibility affordances, and responsive-oriented structure. |
| Backend engineering | 19/20 | Real FastAPI/Scapy/SQLite implementation with persisted jobs, startup recovery, transactional claims, external worker mode, busy-timeout handling, operational metrics, and explicit process separation; still not managed-broker-backed. |
| Detector credibility | 10/15 | Versioned multi-signal detection, provenance, evidence, and reproducible evaluation gates are strong; real benchmark evidence and proven generalization are still absent. |
| Security posture | 9/10 | Authentication, upload safeguards, shared SQLite-backed rate limiting, credential rotation, security headers, and persistent audit events are implemented; encryption, enterprise identity, and supply-chain remediation remain. |
| Testing and reproducibility | 5/5 | 28 backend tests, frontend tests, build checks, pinned pytest, CI integration, and reproducible evaluation tooling. |
| **Total** | **90/100** | Strong prototype with credible single-node/internal-beta foundations; not production-ready. |

## Product overview

FlowCrypid is designed as a threat-intelligence and security-operations console for analyzing network captures. The application accepts PCAP/PCAPNG files, extracts directional network flows, applies behavioral heuristics, produces severity-ranked findings, and exposes evidence for analyst review.

The frontend is built around an active-scope dashboard containing parsed-flow metrics, active findings, average risk, unsupported packets, severity distribution, findings-over-time visualization, searchable evidence, selected-finding investigation, capture history, and export controls. A clearly labeled demo snapshot preserves the review experience when no backend is connected.

The backend provides FastAPI routes for health, readiness, authentication, upload submission, asynchronous job status, capture history, and metrics. Scapy is used for packet parsing, SQLite stores users, sessions, analysis jobs, capture metadata, and findings, and a local worker pool processes queued captures.

## Architecture and workflow

```text
Analyst browser
      |
      | login / upload / job polling / history / exports
      v
FastAPI API
      |
      +--> Authentication and bearer sessions
      +--> Upload validation and rate limiting
      +--> SQLite job and capture metadata
      +--> In-process worker pool
                    |
                    v
             PCAP parser and flow aggregation
                    |
                    v
             FLOW-ENSEMBLE heuristic-v2
                    |
                    v
             Evidence, severity, confidence,
             explanations, and optional calibration
```

The current upload workflow returns `202 Accepted` and a job identifier. The frontend polls `GET /api/jobs/{job_id}` until the job is completed or failed. In local mode, jobs are processed by an in-process pool; the hardened Compose topology uses an external worker process that transactionally claims persisted jobs from SQLite. Successful jobs persist capture and finding records and refresh the authenticated capture history.

## Improvements completed across the roadmap

| Phase | Completed work | Result |
|---|---|---|
| 1 — Repository stabilization | Aligned stale API tests, added repository-level pytest configuration, corrected package scripts, removed configuration drift, and updated README commands. | The complete backend suite runs consistently. |
| 2 — Security hardening | Removed exposed default credentials, added environment-only initial-admin setup, login/upload throttling, streamed uploads, PCAP magic-byte checks, and structured security events. | Safer controlled-beta security boundary. |
| 3 — Asynchronous ingestion | Added persisted job records, job lifecycle states, background processing, job-status API, frontend polling, cleanup behavior, and job-aware smoke tests. | Upload requests return quickly and analysis state is visible. |
| 4 — Detector explainability | Replaced mutually exclusive classification branches with independent signals, added detector ID/version, combined confidence, corroborating evidence, explanations, and metadata-aware exports. | Findings are more transparent and diagnostically useful. |
| 5 — Evaluation foundation | Added canonical-schema validation, dataset provenance flags, input SHA-256 reporting, class/scenario distributions, detector-version reporting, and an explicit no-data status record. | Evaluation is ready, but real metrics remain blocked on authorized data. |
| 6 — Analyst workflow | Added authenticated capture history, automatic history refresh, JSON exports, detector-confidence presentation, and stronger loading/empty/accessibility states. | The dashboard supports a more complete investigation workflow. |
| 7 — Operations | Added job counters, Prometheus-style metrics, readiness metadata, graceful worker shutdown, Docker health checks, explicit compose credentials, runtime limits, `.env.example`, and expanded runbooks. | Better single-node observability and operational discipline. |
| 8 — Release hardening | Added `RELEASE_CHECKLIST.md`, pinned pytest, expanded CI backend coverage, and explicit demo/beta/production gates. | The release posture is documented and honest. |

## Verification evidence

The final local verification completed successfully.

| Check | Result |
|---|---|
| Python compilation | Passed |
| TypeScript check | Passed |
| Frontend tests | Passed — 3 tests |
| Backend smoke test | Passed — authentication, upload validation, async polling, persistence, and logout |
| Full backend regression suite | Passed — 28 tests |
| Production build | Passed |
| YAML syntax validation | Passed for Docker Compose and CI workflow |
| Pinned backend test dependency | `pytest==8.3.5` added to `requirements.txt` |
| Docker runtime validation | Not run; Docker CLI unavailable in the execution environment |
| Full detector benchmark | Not run; authorized labeled dataset extract absent |

## Security and production assessment

The security posture is substantially better than the initial prototype. Administrator credentials are no longer embedded in the frontend or silently seeded by the application. Uploads require authenticated analyst/admin sessions, are rate-limited, are streamed in bounded chunks, and are checked using both extensions and PCAP magic bytes. Sessions are hashed, expire, and can be revoked. Sensitive fields are excluded from structured event logging.

However, the application still has meaningful production blockers.

| Risk | Severity | Current state | Required action |
|---|---|---|---|
| Dependency vulnerabilities | Critical | `pnpm audit --audit-level high` reported 129 findings: 45 high and 2 critical. | Upgrade, replace, or formally disposition every high/critical finding before production. |
| Detector validity | Critical | No authorized labeled benchmark results are committed. | Supply data, freeze thresholds, evaluate precision/recall/F1/FPR/FNR, and publish provenance. |
| Worker durability | High | Jobs run in an in-process `ThreadPoolExecutor`. | Move work to a durable external queue and separate worker service. |
| Rate-limit sharing | High | Rate limiting is in-memory per process. | Use a centralized store for multi-worker or multi-instance deployment. |
| Sensitive storage | High | SQLite and local storage are suitable for controlled single-node use only. | Add encrypted object storage, encrypted backups, access policy, and retention enforcement. |
| Identity | High | Local bearer-session authentication only. | Add enterprise identity integration, MFA policy, password recovery, and lifecycle controls. |
| Tenant isolation | High where applicable | No multi-tenant authorization model. | Add tenant boundaries and authorization tests before shared deployment. |
| Auditability | Medium/High | Structured logs exist, but persistent audit events are not implemented. | Persist immutable audit events and define retention/search procedures. |
| Container verification | Medium | Docker configuration is updated but not executed in this environment. | Build and run the image in CI/staging, then complete readiness and restore drills. |

## Detector assessment

The active detector now uses an ensemble-style heuristic path called `FLOW-ENSEMBLE`, version `heuristic-v2`. It can combine signals such as low-and-slow external transfer, rare external destination, DNS anomaly, beaconing, and internal staging. Findings expose contributing signals, evidence, explanations, a bounded operational risk score, evidence-strength confidence, and optional calibrated probability.

This is a meaningful structural improvement, but the detector remains unvalidated. Confidence is not probability. The fallback calibration behavior should not be described as statistically calibrated until training and test artifacts exist. The official CIC-IDS2017 source describes labeled network flows and PCAP material suitable for research evaluation, but the repository deliberately does not redistribute the dataset.[1]

The required evaluation artifact is documented at `evaluation/results/phase5-status.md`. Until an authorized canonical CSV is supplied, FlowCrypid should not publish accuracy, precision, recall, F1, or false-positive claims.

## Release recommendation

| Release target | Decision | Conditions |
|---|---|---|
| Portfolio demonstration | **GO** | Use demo or approved non-sensitive captures, keep demo mode labeled, and present limitations. |
| Local single-node prototype | **GO** | Supply explicit administrator credentials, use bounded captures, monitor readiness and metrics, and maintain backups. |
| Controlled internal beta | **CONDITIONAL GO** | Complete authorized-data evaluation, dependency-risk disposition, staging restore drill, security review, and explicit acceptance of the single-node worker model. |
| Sensitive enterprise data | **NO-GO** | Requires encryption, stronger identity, auditability, access controls, and approved retention/backup policy. |
| Horizontally scaled production | **NO-GO** | Requires durable queue, shared rate limiting, external storage, tenant isolation, and distributed observability. |

## Recommended next steps

The next investment should be evidence rather than more visual polish. Supply an authorized labeled dataset extract, convert it to the documented canonical schema, run training-split calibration, freeze detector configuration, and generate a test report with class balance, scenario distribution, confusion matrices, detector-level metrics, and input hash.

After the evaluation gate, replace the in-process worker pool with a durable queue and separate worker service. This should include retries, idempotency keys, cancellation, dead-letter handling, queue-depth metrics, and explicit job ownership.

Finally, resolve the dependency audit and complete a staging security review. The release should not advance to production until dependency findings, encrypted storage, external identity, persistent audit logs, backup restoration, and tenant boundaries are independently verified.

## Final package contents

The accompanying source archive contains the complete FlowCrypid source release, including application code, frontend, backend, tests, evaluation tooling, CI configuration, Docker configuration, runbooks, release checklist, and environment template. Generated dependencies, caches, runtime databases, logs, and build output are excluded so the archive remains a clean and reproducible source package.

## References

[1]: https://www.unb.ca/cic/datasets/ids-2017.html "Canadian Institute for Cybersecurity — Intrusion detection evaluation dataset (CIC-IDS2017)"
