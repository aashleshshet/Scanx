# Run the OnescanX platform

The existing Vercel frontend remains at https://onescanx.vercel.app. It works without a backend: inventory import, report exploration, historical comparison, CSV/JSON exports, browser Print / Save PDF, and evidence retrieval run locally in the browser. Samples are explicitly synthetic. Model generation, persistent storage and scheduled worker scans require the services below.

## Local Docker services

Requirements: Docker Engine/Desktop with Compose v2, available ports 8080, and enough memory for PostgreSQL, Redis and Python workers.

```sh
git clone https://github.com/aashleshshet/Scanx.git
cd Scanx
cp .env.example .env
# Edit .env locally; never paste or commit real secret values.
docker compose up --build -d
docker compose ps
```

Set independent random `POSTGRES_PASSWORD` and `ONESCANX_OPERATOR_PASSWORD` values first. The operator password must have at least 16 characters; use 32 or more random characters. Use URL-safe characters for the PostgreSQL password because Compose inserts it into a connection URL. A password manager can generate both. Empty database credentials prevent startup; empty operator credentials prevent login.

Open http://localhost:8080. In **Settings**, connect the platform session using the configured operator password. The website itself is a single-operator workspace; there are no user registration, tenant isolation or billing features.

Only the API port is published, bound to loopback. PostgreSQL and Redis remain on the Docker network. `COOKIE_SECURE=false` in Compose is exclusively for this HTTP loopback deployment. Containers run the Python services as a non-root user. Database and broker data use named volumes. Stop with `docker compose down`; retain the volumes to retain reports. Do not use `down -v` unless intentionally deleting all local data.

## Register and assess an owned API

1. Add the exact HTTPS API root to `ONESCANX_TARGETS`, for example `['...']` **as valid JSON with double quotes**: `["https://your-api.example/v1"]`. Recreate API/worker/Beat after environment changes.
2. In **API Inventory**, upload OpenAPI JSON, enter the API name and root, and optionally select scenario JSON/YAML. The backend parser supports OpenAPI/Swagger JSON/YAML; the browser-only inventory currently accepts JSON.
3. For paired-user tests, copy `examples/scenarios.yaml`, replace fixture IDs and change credential references to `ONESCANX_SCAN_TOKEN_A` and `ONESCANX_SCAN_TOKEN_B`. Set those variables in the worker environment. Do not put token literals into fixture files, specifications or reports.
4. Register the specification. Publish the displayed random challenge at `https://your-api.example/.well-known/onescanx-verification.txt`. Keep a copy of the challenge until verification succeeds. Registration never sends scan traffic.
5. Click **Verify ownership**. The challenge must return HTTP 200, no redirect, and only the token. Ownership remains valid for seven days. Reverify to renew it.
6. In **New Security Scan**, select the verified API and queue an assessment. Refresh worker jobs to see queued/running/complete/error. Open the completed report from **Reports → Platform reports**.
7. Set an interval to schedule the selected API. Run exactly one worker and one Beat instance in this MVP. Expired ownership suspends scheduled execution. Remove a schedule to stop future runs.

Only public HTTPS targets on port 443 are supported by platform workers. Private/local targets remain available through the existing explicitly configured local scanner, `scanx-web --target ...`; they are intentionally unavailable through the hosted worker path. Workers run read-only BOLA, authentication, header and CORS checks with a 300-request budget, 3 requests/second and a 180-second scan deadline. Existing CLI/local injection and burst modules remain opt-in.

## Optional cloud connections

Use the **existing** Vercel project `scanx`; do not create a replacement project or alter its Vercel Authentication settings. Host the API, worker and Beat as containers on an appropriate service. Provision PostgreSQL and Redis with authentication, TLS, backups and private access. Set `DATABASE_URL` (`postgresql+psycopg://…`) and `REDIS_URL` (`rediss://…` when required by the provider) through that service's secret manager.

Run `python -m api_sentry.platform.migrate` once before deploying API and workers. Use HTTPS for the backend, `COOKIE_SECURE=true`, an explicit `ONESCANX_ORIGINS`, an operator password and an exact target allowlist. Disable proxy access logs containing cookies/bodies; retain action-only audit events. Add a reverse-proxy request limit and egress firewall as defense in depth.

Set only these connection variables on the existing Vercel project:

| Variable | Purpose |
| --- | --- |
| `ONESCANX_BACKEND_URL` | Fixed backend HTTPS origin, without credentials/query/fragment |
| `ONESCANX_BRIDGE_KEY` | Random bridge secret, matching the backend value |

Keep database, Redis, scan-token and AI credentials exclusively on the backend. The bridge forwards the scoped HttpOnly session cookie; it never returns its own secret. It accepts only known API paths and same-origin changes. Vercel Authentication continues protecting the hosted website; the optional backend has a separate operator session.

## Optional AI synthesis

Set `AI_API_KEY`, `AI_MODEL` and optionally `AI_API_URL` on the backend. The default URL is Vercel AI Gateway's OpenAI-compatible HTTPS chat-completions endpoint. Choose a model supporting JSON output. No provider account is provisioned automatically.

Open a report in **AI Assistant**, enter a question, and explicitly allow selected finding metadata to reach the configured provider. Only eight retrieved findings, the question and bundled OWASP guidance are sent; raw response bodies and scan credentials are excluded. Reports can still contain sensitive information supplied by the importer—review them before consenting. Without configuration or consent the assistant returns evidence only. Model text is advisory and cannot modify scanner findings. Invalid citations are rejected.

## Development and checks

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev,web,platform]'
ruff check .
ruff format --check .
pytest -q
pnpm install --frozen-lockfile
pnpm test
pnpm build
pnpm exec playwright install chromium
pnpm test:e2e
```

SQLite is supported for isolated tests/local development. `DATABASE_URL=sqlite:///onescanx.db python -m api_sentry.platform.migrate` initializes it. Use PostgreSQL for persistent container hosting. The GitHub importer is provided by the Next.js frontend and accepts explicit public repository JSON paths; private OAuth and browser YAML parsing are not implemented. The Docker-only UI can import local specification files instead.

Troubleshooting: 401 → reconnect the operator session; 403 → check same-origin/target approval/ownership; 422 → validate specification and fixtures; 429 → wait for the one-minute API limit; 503 → configure missing services; queued jobs → verify worker and Redis are running. A worker error intentionally omits sensitive exception details.
