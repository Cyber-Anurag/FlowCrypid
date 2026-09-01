# FlowCrypid — Updated Project Audit

**Review context:** College-level project submission  
**Review date:** 30 August 2026  
**Overall assessment:** Strong student prototype with an excellent presentation layer and an incomplete proof and backend layer.

## Executive verdict

FlowCrypid is a credible threat-intelligence dashboard prototype focused on behavioral anomalies and possible low-and-slow data exfiltration. The upgraded submission has a clear visual system, a coherent analyst workflow, typed frontend/API boundaries, responsive-oriented layout, severity filtering, timeline visualization, CSV export, PCAP ingestion controls, and a selected-finding investigation view.

The project is strongest as a **product and interface demonstration with a working local analysis path**. The archive now includes the FastAPI PCAP parser, flow aggregation, rule-based detector, authentication layer, SQLite persistence, evaluation runner, calibration utilities, and explanation metadata. The demo snapshot remains clearly labeled, which is appropriate, but it cannot substitute for detector validation on representative data.

> **Fair college-level score: 82/100.** The work is substantially above average for a student project and has strong portfolio potential. The score would be lower under a production-readiness rubric because the backend, testing, and evaluation evidence are incomplete.

## Rubric

| Area | Score | Assessment |
|---|---:|---|
| Problem framing | 14/15 | The project addresses a specific and meaningful cybersecurity problem rather than presenting a generic dashboard. |
| Conceptual understanding | 14/15 | The design communicates awareness of network flows, behavioral anomalies, risk scoring, severity tiers, temporal context, evidence, and analyst investigation. |
| Visual design and UX | 18/20 | The SOC-style interface is distinctive, coherent, information-dense, and materially more polished than a typical student dashboard. |
| Functional frontend depth | 13/15 | Search, severity filters, timeline aggregation, CSV export, upload controls, demo fallback, and investigation details are implemented in the frontend. |
| Engineering quality | 12/15 | The repository now includes a working backend, SQLite persistence, secure local configuration, Vite proxy, Compose deployment, and pinned Python dependencies. |
| Testing and validation | 8/10 | Secure backend smoke tests cover authentication, authorization, protected upload, persistence, invalid files, and logout. A benchmark runner now supports overall and detector-level metrics, but real dataset results still need to be generated. |
| Documentation and reproducibility | 9/10 | The README, deployment guide, evaluation guide, canonical schema, calibration workflow, and API configuration are aligned with the upgraded code. |
| **Total** | **82/100** | **Strong college project; not yet a production-ready detection system.** |

## What the upgraded submission does well

### 1. It has a clear product story

The dashboard is organized around a plausible security-operations workflow. A reviewer can move from high-level telemetry to severity distribution, inspect findings over time, filter the evidence log, search by network indicator, select a finding, and review its source, destination, observed window, signals, and evidence.

### 2. The interface has a deliberate visual identity

The dark operations-console treatment, cyan and severity accents, compact metadata, panel structure, and consistent iconography give FlowCrypid a recognizable identity. The result feels like a designed product surface rather than an unmodified component-library starter.

### 3. The frontend implementation has a sensible structure

`client/src/App.tsx` contains the dashboard workflow, while `client/src/lib/api.ts` handles API requests and `client/src/lib/flowcrypid.ts` defines response contracts, normalization, severity helpers, and timestamp handling. This separation is appropriate for a student prototype and makes the frontend easier to extend.

### 4. The demo state is honest

The submission labels the disconnected state as **DEMO MODE** and identifies the ML model as **DEMO** when no health response is available. This is much better than silently presenting fabricated findings as live security telemetry.

### 5. The basic technical verification passes

The submitted project successfully completes the following checks from the repository root:

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm build
pnpm test:backend
```

The TypeScript check, production build, Python compilation, and secure backend smoke test complete successfully. The smoke test verifies unauthorized upload rejection, login, authorized upload, SQLite capture persistence, invalid extension rejection, and session revocation. Browser inspection confirms that the dashboard renders and that severity filtering updates the findings table and timeline.

## Important limitations

### 1. The backend is intentionally lightweight

The archive includes a real FastAPI backend with PCAP/PCAPNG parsing, directional flow aggregation, transparent heuristic detectors, server-side upload limits, authentication, role checks, and SQLite persistence. It is reproducible for local evaluation, but it remains a lightweight prototype rather than a horizontally scaled production analysis service. It does not yet provide background jobs, durable object storage, multi-tenant isolation, or a calibrated ML model by default.

### 2. Evaluation results must still be generated from authorized real data

The repository now includes an evaluation README, a canonical labeled-flow schema, a benchmark runner, detector-level metrics, and Platt calibration utilities. It references the official CIC-IDS2017 source without redistributing its records. Until an authorized dataset extract is prepared and evaluated, the project must not claim measured precision, recall, false-positive rate, robustness, or generalization.

### 3. Production security hardening is incomplete

The backend now independently enforces file extension, size, packet-count, empty-file, malformed-capture, authentication, role, and temporary-file controls. It uses hashed passwords, hashed bearer sessions, expiration, revocation, CORS configuration, and SQLite persistence. Operational controls now include structured logs, readiness/metrics endpoints, retention cleanup, privacy redaction, backup/restore tooling, dependency scanning, secret scanning, and runbooks. Before handling sensitive enterprise captures, it still needs an external identity provider, rate limiting, centralized audit-log retention, encryption/key management, secret rotation, stronger content inspection, encrypted off-host backups, alerting, and a formal threat-model review.

### 4. Test depth and benchmark coverage should expand

The current smoke test covers the protected backend path, but broader unit, integration, parser, detector, frontend, security, and performance tests are still required for production confidence. The benchmark runner is ready for real labeled data, but no benchmark result should be considered representative until the dataset is prepared, split, evaluated, and reviewed.

### 5. Minor build and maintenance warnings remain

The production build no longer reports the previous undefined analytics placeholder warnings, and chart/icon code is split into separate chunks. The project still needs deeper load testing and centralized monitoring validation before production traffic is accepted.

## Recommended improvements before final submission

| Priority | Action | Reason |
|---|---|---|
| High | Keep the top-level README explicit about the included backend and remaining production gaps. | Prevents reviewers from confusing the local prototype with a production-scale analysis service. |
| High | Prepare an authorized CIC-IDS2017-derived canonical CSV and run the test-split benchmark. | Produces real, reviewable detector metrics rather than demo claims. |
| High | Fit calibration only on the training split and freeze the calibration file before test evaluation. | Prevents the displayed probability from being mistaken for an unvalidated raw score. |
| High | Expand tests across parsers, detectors, API security, frontend behavior, and performance. | Demonstrates reliability beyond the smoke-test path. |
| High | Add rate limiting, audit logging, encryption, secret rotation, and stronger upload content inspection. | Closes the largest remaining production-security gaps. |
| Medium | Add background analysis jobs and durable object storage. | Prevents long PCAPs from blocking API workers and improves operational resilience. |
| Medium | Resolve analytics-template and bundle-size warnings. | Removes avoidable build and performance debt. |
| Medium | Add a screenshot or short demo video to the submission. | Ensures the strongest part of the project—the interface—is evaluated immediately. |
| Medium | Configure centralized log shipping, alert rules, encrypted off-host backups, and a scheduled restore drill. | Converts local operational tooling into a dependable production process. |

## Final assessment

FlowCrypid is a strong college-level submission because it combines a serious problem, meaningful technical ambition, an unusually polished interface, and a clear product narrative. It should be submitted as a **threat-intelligence dashboard prototype** or **security-operations interface for PCAP-analysis results**.

It should not be described as a fully production-ready cybersecurity platform yet. The main opportunity is now to close the evidence loop: run the benchmark on authorized real data, freeze and report calibration honestly, expand security and performance testing, and add operational controls for sensitive captures.

**Final college-level score: 82/100.**

**Best one-line summary:** FlowCrypid now has a reproducible secure local backend and explainable evaluation path; the next stage is proving its detector works beyond the demo snapshot.
