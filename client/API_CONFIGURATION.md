# API URL configuration

The dashboard no longer hard-codes an API host. `client/src/lib/api.ts` reads `VITE_API_BASE_URL` from Vite at build time. If the variable is empty or undefined, requests use relative paths such as `/api/health` and `/api/upload`, which is the recommended production mode behind the included Nginx reverse proxy.

For local development with the original FastAPI service running on port 8000, launch the frontend with `VITE_API_BASE_URL=http://localhost:8000 pnpm dev`. For a separate deployed backend, set the variable to its HTTPS origin during the frontend build, for example `VITE_API_BASE_URL=https://api.example.com`.

The 50 MB browser check is a usability guard. The backend and reverse proxy enforce their own upload limits independently. Uploads require a bearer token obtained from `POST /api/auth/login`; the dashboard stores that token locally for the session and sends it with `POST /api/upload`. Capture metadata and findings are persisted in the backend SQLite database under `storage/flowcrypid.db`. The seeded development administrator is `admin@flowcrypid.local` / `FlowCrypid-dev-2026`; change these values before any non-local deployment.

Available protected endpoints include `GET /api/auth/me`, `POST /api/auth/logout`, and `GET /api/captures`. The current role model supports `admin` and `analyst`; both roles may inspect captures and upload files. The backend uses server-side role checks even if a request bypasses the frontend.
