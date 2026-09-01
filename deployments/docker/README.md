# FlowCrypid local deployment

The repository now includes both the React/Vite frontend and a FastAPI backend. The backend queues PCAP/PCAPNG uploads, processes them with an in-process worker pool, persists job status in SQLite, aggregates directional flows, and returns typed heuristic findings for the dashboard.

## Docker Compose

From the repository root:

```bash
docker compose up --build
```

Open `http://localhost:8080`. Nginx serves the frontend and proxies `/api/*` to the healthy `backend` service. Stop the stack with:

```bash
docker compose down
```

The backend container uses `deployments/docker/Dockerfile.backend`, `requirements.txt`, `apps/`, and `models/`. The frontend container uses `deployments/docker/Dockerfile.frontend` and serves the compiled Vite output through Nginx. SQLite data is persisted through the repository `storage/` volume.

## Local development without Docker

Install the Python dependencies and start the backend:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn apps.api.main:app --reload --port 8000
```

In a second terminal, install the frontend dependencies and start Vite:

```bash
pnpm install --frozen-lockfile
pnpm dev
```

The Vite development server proxies `/api/*` to `http://localhost:8000` by default. Set `VITE_DEV_API_PROXY` if the backend uses another local origin.

## API endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Reports service status and parser/model components. |
| `POST /api/auth/login` | Validates credentials and returns a short-lived bearer session token. |
| `GET /api/auth/me` | Returns the authenticated user identity and role. |
| `POST /api/auth/logout` | Revokes the current bearer session. |
| `POST /api/upload` | Requires an analyst/admin bearer token; accepts `.pcap` or `.pcapng`, queues analysis, and returns a job ID with `202 Accepted`. |
| `GET /api/jobs/{job_id}` | Requires an analyst/admin bearer token and returns queued, processing, completed, or failed job status. |
| `GET /api/captures` | Requires an analyst/admin bearer token and returns authorized completed capture history. |

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `FLOWCRYPID_ALLOWED_ORIGINS` | Comma-separated CORS origins. | `http://localhost:3000` |
| `FLOWCRYPID_MAX_UPLOAD_BYTES` | Maximum upload size enforced by the API. | `52428800` |
| `FLOWCRYPID_MAX_PACKETS` | Maximum packets processed per capture. | `500000` |
| `FLOWCRYPID_VERSION` | API version shown by the health endpoint. | `1.1.0` |
| `FLOWCRYPID_DB_PATH` | SQLite database location. | `storage/flowcrypid.db` |
| `FLOWCRYPID_SESSION_TTL_SECONDS` | Session lifetime. | `28800` |
| `FLOWCRYPID_ADMIN_EMAIL` | Initial administrator email; required with the password for first setup. | None |
| `FLOWCRYPID_ADMIN_PASSWORD` | Initial administrator password; minimum 12 characters. | None |
| `FLOWCRYPID_WORKER_COUNT` | Number of in-process background analysis workers. | `2` |
| `VITE_API_BASE_URL` | Frontend API origin at build time. | Empty, using same-origin paths. |

The API enforces its own upload and packet limits. The browser’s 50 MB check remains a usability guard and must not be treated as the only security boundary.

## Scope and limitations

The included backend is intentionally lightweight and suitable for local demonstration and student-project evaluation. It now provides bearer-session authentication, analyst/admin role checks, SQLite persistence, server-side upload and packet limits, temporary-file cleanup, asynchronous in-process job processing, and transparent heuristic classification. It does not yet provide password-reset flows, an external identity provider, a separate durable queue worker, calibrated machine-learning inference, multi-tenant isolation, or production observability. The in-process worker pool is not suitable for horizontally scaled deployments; move jobs to a shared durable queue before production use.
