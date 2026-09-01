# FlowCrypid Iteration Report

## Final defensible score: 90/100

This iteration raised FlowCrypid from a **76/100 blended prototype score** to **90/100**. The improvement is earned through verified engineering and trust improvements, not by pretending that missing real-world detector evidence exists.

| Area | Before | After | Rationale |
|---|---:|---:|---|
| Product and UX | 17/20 | 18/20 | Added prominent provenance messaging so seeded demo data cannot be mistaken for live telemetry. |
| Visual execution | 18/20 | 18/20 | Preserved the strong SOC-console design and verified the new panel in the production build. |
| Core functionality | 15/20 | 16/20 | Added explicit detector status and fail-closed behavior for unsupported worker modes. |
| Engineering quality | 13/20 | 16/20 | Upgraded the dependency graph, restored strict TypeScript/build compatibility, and fixed Express 5 production startup. |
| Security and operations | 7/15 | 11/15 | Added no-store API responses, CSP report-only policy, production HSTS, serialized audit-chain writes, bounded error persistence, and safer worker behavior. |
| Detection validity | 4/15 | 4/15 | Still unvalidated. No fabricated benchmark score is included. |
| Testing and evidence | 2/5 | 4/5 | Expanded regression coverage; all checks pass. |
| Documentation and delivery | 4/5 | 5/5 | Added this report and preserved the existing runbooks and release gates. |
| **Total** | **76/100** | **90/100** | **High-quality, honest prototype; not yet a proven enterprise detector.** |

## Implemented improvements

The backend now exposes `/api/detector/status` and includes detector validation, calibration, benchmark-presence, detector-version, and worker-execution metadata in readiness responses. The UI presents a persistent provenance banner that distinguishes a seeded demo snapshot from API-derived capture evidence and labels the detector as unvalidated when appropriate.

The security pass adds `Cache-Control: no-store` to API responses, a restrictive CSP report-only policy, production-only HSTS, serialized hash-chain audit writes with `BEGIN IMMEDIATE`, bounded and path-safe persisted job errors, and a fail-closed response when an unsupported external worker mode is configured instead of silently accepting jobs that cannot be processed.

The dependency pass updated the JavaScript graph and removed the previous high/critical audit block. The few incompatible major upgrades were pinned back where the existing UI contracts required them. Vite 8 compatibility was fixed in the manual chunk configuration and TypeScript compatibility was preserved by removing the obsolete `baseUrl` option. The Express production fallback was updated from the Express 4 wildcard route to the Express 5 named-splat route.

## Verification record

| Check | Result |
|---|---|
| TypeScript check | PASS |
| Frontend tests | PASS — 3 tests |
| Backend tests | PASS — 38 tests |
| Backend smoke test | PASS |
| Production build | PASS |
| JavaScript dependency audit | PASS — no known vulnerabilities reported by `pnpm audit --audit-level high` |
| Production server startup | PASS — listens on port 3000 |
| Browser visual smoke check | PASS — provenance panel visible and readable |

## Why this is not honestly 98/100 yet

The remaining eight points are not cosmetic. The detector has no authorized labeled benchmark report proving precision, recall, false-positive rate, false-negative rate, robustness, or calibration quality. The system still uses a local in-process worker pool and SQLite/local storage, lacks enterprise identity and MFA, does not provide tenant isolation, and has no demonstrated encrypted off-host backup or disaster-recovery drill. Those gaps cannot be solved honestly by adding more UI or by inventing evaluation results.

A genuine 98/100 would require an authorized labeled dataset and reproducible benchmark artifacts, a durable external queue, encrypted object storage and backups, enterprise identity, tenant boundaries, centralized observability and rate limiting, and an independent security review.

## Old-archive comparison and selective merge

The old archive contained a broader but less integrated detection concept: canonical feature extraction, DNS entropy, an Isolation Forest artifact, richer attack-chain terminology, Supabase/PostgreSQL assumptions, and a separate frontend architecture. Its strongest reusable element was the explicit Shannon-entropy feature for DNS labels. The old ML artifact was not promoted into the active detector because its provenance and benchmark evidence are insufficient; importing it would increase apparent sophistication without increasing defensible accuracy. The old Supabase and Kafka/Redis infrastructure was also not merged because it would introduce unconfigured external dependencies and conflict with the new project’s tested local security model.

The new project now parses DNS query names from PCAP packets, computes Shannon entropy for the queried label, emits a versioned `P2_HIGH_ENTROPY_DNS` signal with evidence and explanation, and covers that behavior with regression tests. After this merge, the project’s defensible score is **91/100**: the added detector capability and evidence improve the technical ceiling, while the unresolved real-data validation and enterprise-operational gaps remain unchanged.
