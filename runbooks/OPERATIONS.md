# FlowCrypid operations runbook

This runbook is for the included local or single-node deployment. It is not a substitute for an organization’s incident-response policy.

## Service health

Check liveness, readiness, and request metrics:

```bash
curl -fsS http://localhost:8000/api/health/live
curl -fsS http://localhost:8000/api/health/ready
curl -fsS http://localhost:8000/api/metrics
```

A live response confirms the process is running. A ready response confirms the SQLite store can be opened. Metrics are in Prometheus text format and should be scraped by the deployment’s monitoring system rather than exposed publicly without an access-control decision. The metrics endpoint includes request totals, recent average latency, analysis-job lifecycle totals, and configured worker count. The readiness response additionally reports the active detector version.

## Analysis jobs

Upload submission is asynchronous. Confirm a job is moving through `queued`, `processing`, and `completed` with:

```bash
curl -fsS -H "Authorization: Bearer $FLOWCRYPID_TOKEN" \
  http://localhost:8000/api/jobs/JOB-... | jq
```

A `failed` job preserves its error reason in SQLite and removes its temporary capture file. The Docker Compose deployment runs the API with `FLOWCRYPID_WORKER_MODE=external` and starts a separate worker process that claims queued jobs transactionally from the shared SQLite database. This survives API restarts and prevents PCAP parsing from consuming API worker threads. The queue is still database-backed rather than a managed broker; use Redis, RabbitMQ, SQS, or another durable broker before high-volume horizontal scaling.

The default `FLOWCRYPID_RATE_LIMIT_BACKEND=sqlite` stores request buckets in the shared database, so limits are consistent across the API and worker processes on one node. A centralized Redis-backed limiter is still recommended for independent replicas or multiple hosts.

## Deployment configuration

Copy `.env.example` to a protected environment file, replace the administrator values, and never commit the resulting file:

```bash
cp .env.example .env
# edit .env with a unique administrator password
set -a; . ./.env; set +a
docker compose config
docker compose up --build
```

The compose file requires administrator credentials explicitly, uses the readiness endpoint for health checks, and applies a 1 GB memory and 2 CPU limit to the backend. Review these limits against capture size and packet-count settings before increasing them.

## Backup

Create a verified SQLite backup before upgrades or destructive maintenance:

```bash
python3 scripts/backup_restore.py backup \
  --source storage/flowcrypid.db \
  --destination backups/flowcrypid-$(date -u +%Y%m%dT%H%M%SZ).db
```

The command runs an integrity check, uses SQLite’s online backup API, refuses to overwrite an existing backup, and writes a SHA-256 manifest beside the backup. Copy the database and manifest to protected storage with access controls separate from the application host.

## Restore drill

Restore to a new path first. Never overwrite the live database during an incident:

```bash
python3 scripts/backup_restore.py restore \
  --source backups/flowcrypid-YYYYMMDDTHHMMSSZ.db \
  --destination storage/flowcrypid-restored.db
```

Verify the restored database, compare expected capture counts, and record the recovery point before switching the application to it. Preserve the original database for forensic review.

## High-severity incident response

When suspicious or malicious activity is reported, preserve relevant capture IDs, timestamps, user identity, request logs, and detector explanations. Do not upload additional sensitive captures to an unapproved environment. If credentials may be compromised, revoke active sessions by removing or rotating the session store and change the administrator credential through the deployment environment.

For a suspected application compromise, stop external access, preserve logs and the SQLite file, take a backup, rotate secrets, inspect the dependency and container scan results, and redeploy from a known-good commit. Record the incident timeline, affected captures, actions taken, and validation evidence.

## Common failures

| Symptom | First checks | Safe response |
|---|---|---|
| Readiness fails | SQLite path, permissions, disk space, integrity check | Stop writes, copy the database, repair or restore to a new path. |
| Upload returns 401 | Session expiry, Authorization header, clock skew | Sign in again; do not disable authentication. |
| Upload returns 413 | Reverse-proxy and API limits, capture size | Reduce the capture or explicitly change limits after a capacity review. |
| Analysis is slow | Packet count, memory, CPU, request duration metrics | Use a bounded capture and schedule background processing before increasing limits. |
| Findings disappear | Retention setting, database path, mounted volume | Verify `FLOWCRYPID_RETENTION_DAYS` and storage volume before restarting. |

## Change management

Back up before schema or dependency changes. Run `pnpm test`, `pnpm check`, `pnpm build`, the backend smoke test, Python compilation, dependency scanning, a compose configuration validation, readiness/metrics checks, and a restore drill in staging. Record the commit, configuration changes, migration status, worker count, resource limits, and rollback plan.
