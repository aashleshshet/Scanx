# Validation record

## Intelligence workspace MVP — 5 November 2026

Executed locally on Python 3.12 / Node 22+:

| Check | Result |
| --- | --- |
| Python suite | 70 passed, 1 infrastructure test skipped |
| Ruff lint and formatting | Passed |
| Node unit tests | 6 passed |
| Next.js production build | Passed; existing pages plus platform/GitHub API routes |
| Production JavaScript dependency audit | No known vulnerabilities found |
| Backend API tests | Session expiry/logout/CSRF, target approval/ownership, scheduling, credential reference restrictions, report storage, PDF/CSV and validation errors passed |
| Worker integration with synthetic transport | Actual scanner engine completed and persisted report |
| AI boundary tests | Untrusted input separated from system policy; unknown citations rejected; no-consent fallback passed |
| Browser checks | All workspace destinations opened; desktop overflow/branding checks passed; OpenAPI JSON import produced correct auth declarations; mobile More menu and evidence assistant exercised |

One installed Starlette TestClient deprecation warning refers to its HTTPX adapter. Docker is unavailable on this development machine: the full Compose stack and live PostgreSQL/Redis processes were not run locally. A dedicated GitHub Actions job tests the PostgreSQL → Redis → Celery → database round trip; Playwright/axe and Python dependency/secret checks are also configured. Their results must be read from the exact commit's CI run, not inferred from this local record.

The optional LLM was tested with mocked provider responses, not a real configured model. No hosted backend, worker, database or model credentials were provisioned. No arbitrary external API was scanned. Manual browser checks do not establish full screen-reader or physical-device conformance.

Taste's static lint flags the existing gradients, shadows and glass effects. These are retained as explicit requirements of the user's Liquid Glass brief; the lint is not reported as passing. Impeccable's launcher could not initialize its cache; its review guidance was applied manually. Mobile primary navigation was reduced to four routes plus a complete More menu, and report-dependent pages retain source labels.

The original scanner validation below remains applicable; its dated counts describe the earlier baseline.

Validated on 2 November 2026 with Python 3.12 on macOS ARM64. All scanner tests use `httpx.MockTransport` or synthetic observations. The web UI was also exercised against a synthetic HTTP API on loopback; no external API was scanned.

| Check | Result |
|---|---|
| `pytest -q` | 58 passed |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed |
| Package build/install | Wheel built and installed into an isolated temporary target |
| Installed CLI | Help, specification inspection and schema generation smoke checks |
| Generated JSON Schema | Draft 2020-12 schema validated |
| Sample JSON reports | Both validated against schema, including timestamp formats and summary counts |
| HTML/Markdown handling | Escaping and redaction tests passed; no scripts or remote images in sample HTML |
| Web visual preview | HTTP browser preview, filters, sample switching, details, local scan and JSON export checked |

Tests cover numeric and UUID IDs in path/query locations; bidirectional private-object disclosure; protected, public and ambiguous responses; identical effective credentials; authentication scheme composition; cookie isolation; redirect suppression; origin/base-prefix handling; bounded responses; compressed-response rejection; input aliases/duplicates/deep nesting; request budgets; cancellation/deadlines; explicit write/probe opt-ins; burst count/concurrency; syntax/timing signal classification; report validation/escaping/redaction/file permissions; and CI exit codes.

The timing classifier was tested using synthetic durations, including noisy controls and timeouts. No actual database or shell timing payload was executed. This establishes implementation behavior under fixtures, not detection accuracy for an arbitrary live API.

## Synthetic end-to-end results

| API fixture | Requests | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|---:|
| Vulnerable | 75 | 0 | 2 | 1 | 7 |
| Protected | 73 | 0 | 0 | 0 | 0 |

The vulnerable fixture exposes both cross-user object directions, a simulated SQL error, missing HTTPS HSTS, wildcard-with-credentials CORS and no HTTP 429 in the tested burst. The protected fixture denies cross-user reads and returns HTTP 429 during its burst. The sample reports explicitly identify all responses as synthetic.

## Dependency versions used

| Dependency | Version |
|---|---|
| HTTPX | 0.28.1 |
| PyYAML | 6.0.3 |
| Pydantic | 2.14.2 |
| pytest | 9.2.0 |
| jsonschema | 4.26.0 |
| Ruff | 0.17.3 |
| setuptools | 84.1.0 |

The GitHub Actions matrix is configured for Python 3.11, 3.12 and 3.13. Only Python 3.12 was executed in this workspace. Dependency ranges in `pyproject.toml` are not a platform-specific lockfile; resolve and commit one for a release environment.

## Web application validation

The additional six tests cover allowed targets, host/origin restrictions, upload limits, validation error redaction, explicit per-job credentials, downloads, cancellation, concurrency, and sample report schemas. A browser-driven assessment against a synthetic local server completed 22 requests across 3 operations and 4 modules, producing two expected High BOLA findings. Browser console had no errors. The beginner walkthrough and copyright pages were added on 3 November 2026.
