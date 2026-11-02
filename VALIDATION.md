# Validation record

Validated on 2 November 2026 with Python 3.12 on macOS ARM64. All scanner tests use `httpx.MockTransport` or synthetic observations. No live API was scanned.

| Check | Result |
|---|---|
| `pytest -q` | 52 passed |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed; 26 Python files |
| Package build/install | Wheel built and installed into an isolated temporary target |
| Installed CLI | Help, specification inspection and schema generation smoke checks |
| Generated JSON Schema | Draft 2020-12 schema validated |
| Sample JSON reports | Both validated against schema, including timestamp formats and summary counts |
| HTML/Markdown handling | Escaping and redaction tests passed; no scripts or remote images in sample HTML |
| HTML visual preview | Not performed: browser policy blocked the local-file URL |

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
