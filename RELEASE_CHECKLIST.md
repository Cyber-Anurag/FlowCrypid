# FlowCrypid release checklist

## Release decision

**Current recommendation: GO for portfolio demonstration and controlled local demo. CONDITIONAL GO for internal beta only after the security gates below are accepted. NO-GO for production handling of sensitive enterprise captures.**

The current release contains a polished frontend, authenticated capture ingestion, asynchronous in-process analysis, SQLite persistence, versioned multi-signal heuristic findings, operational metrics, and documented recovery procedures. It does not yet have validated detector performance on an authorized labeled dataset, a durable distributed queue, centralized rate limiting, encrypted storage and backups, external identity management, multi-tenant isolation, or a resolved dependency audit. Persistent security audit events and startup recovery for interrupted local jobs are now implemented, but remain single-node features.

## Evidence record

| Gate | Status | Evidence or blocker |
|---|---|---|
| Python compilation | PASS | `python3 -m py_compile apps/api/main.py apps/api/calibration.py scripts/*.py` |
| TypeScript check | PASS | `pnpm check` |
| Frontend tests | PASS | 3 tests passing |
| Backend smoke test | PASS | Auth, upload validation, async job polling, persistence, and logout verified |
| Full backend suite | PASS | 28 tests passing |
| Production frontend/backend build | PASS | `pnpm build` succeeds |
| Detector evaluation | BLOCKED | No authorized canonical labeled dataset is present; see `evaluation/results/phase5-status.md` |
| Dependency audit | FAIL / ACCEPTANCE BLOCKER | `pnpm audit --audit-level high` reports 129 vulnerabilities: 9 low, 73 moderate, 45 high, 2 critical |
| Python dependency audit | MUST RUN IN CI | CI invokes `pip-audit -r requirements.txt` |
| Secret scanning | CI GATE | TruffleHog verification is configured in CI |
| Docker validation | ENVIRONMENT BLOCKED | Docker CLI unavailable in the current sandbox; compose changes were statically reviewed |
| Restore drill | DOCUMENTED | Run against a staging copy before beta approval |
| Durable queue | NOT READY | Jobs are persisted and interrupted local jobs are recovered at startup, but the worker pool remains in-process and is not horizontally scalable |

## Minimum portfolio-demo gate

A portfolio demo may proceed when the standard build and test checks pass, the demo mode is clearly labeled, no real sensitive captures are used, and the known limitations are presented alongside the product.

## Minimum internal-beta gate

An internal beta requires a supplied authorized labeled dataset and a committed evaluation report; a dependency-audit disposition for all high and critical findings; a staging restore drill; a review of administrator credential setup; rate-limit testing; and a documented decision that the local worker pool is acceptable for the selected single-node deployment.

The beta must use non-sensitive or explicitly approved captures until storage encryption, access policy, and backup controls are verified.

## Production gate

Production approval is **not granted** by this release. Production requires a durable external queue, shared rate limiting, encrypted object storage and backups, external identity or equivalent enterprise authentication, multi-tenant isolation where applicable, a security review, detector evaluation and calibration evidence, container vulnerability remediation, and a tested disaster-recovery procedure.

## Release procedure

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
python3 -m py_compile apps/api/main.py apps/api/calibration.py scripts/*.py
pnpm audit --audit-level high
pip-audit -r requirements.txt
```

For a staging deployment, set administrator credentials through a protected environment file, validate the compose configuration, check `/api/health/live`, `/api/health/ready`, and `/api/metrics`, submit a bounded PCAP, poll its job to completion, create a verified backup, restore to a new database path, and record the results.

## Rollback

Stop external access, preserve logs and the current database, create a verified backup, revert to the last known-good application artifact, restore the database only to a new path if required, and validate readiness before reopening access. Never overwrite the original database during incident recovery.

## Known limitations carried forward

FlowCrypid remains a **heuristic and unvalidated detector**. Confidence is evidence strength, not calibrated probability unless a validated calibration artifact is present. Analysis jobs are persisted and interrupted local jobs are recovered at startup, but execution remains an in-process worker pool. Persistent audit events exist, while metrics remain local counters and are not a replacement for centralized observability. SQLite is suitable for the included single-node deployment but not for an unmodified multi-instance production topology.
