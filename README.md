# Scanx

Scanx is a Python 3.11+ CLI (installed as `api-sentry`) for specification-driven REST API security testing. It includes a bounded async engine, a complete paired-user BOLA module, focused authentication/header/CORS/injection/rate checks, and versioned JSON plus executive Markdown/HTML reports.

Use it against APIs you are authorized to test. Start with seeded test accounts and private fixture objects in a staging environment. This is a tested portfolio foundation with explicit coverage limits; production readiness also depends on the target API's authorization policy, deployment constraints and integration tests.

## Project structure

```text
Scanx/
├── pyproject.toml
├── README.md
├── .github/workflows/ci.yml
├── src/api_sentry/
│   ├── cli.py                   # argparse, validation and CI exit codes
│   ├── config.py                # environment-backed identities and request/BOLA fixtures
│   ├── models.py                # typed domain objects, findings, check results, report
│   ├── spec.py                  # OpenAPI/Swagger normalizer and local-reference resolver
│   ├── transport.py             # scope, authentication, pacing, concurrency and budgets
│   ├── engine.py                # worker queue, module contract, deadlines, partial scans
│   ├── reporting.py             # JSON Schema, redaction, escaping and atomic report writes
│   └── checks/
│       ├── bola.py              # complete bidirectional private-object experiment
│       ├── auth.py
│       ├── headers.py
│       ├── cors.py
│       ├── injection.py
│       └── rate_limit.py
├── schemas/report.schema.json   # generated from the same model used at runtime
├── examples/
│   ├── openapi.yaml
│   ├── scenarios.yaml
│   ├── demo.py                  # in-process synthetic API; no network needed
│   └── sample-reports/          # generated demonstration output
└── tests/                      # MockTransport tests, with no live targets
```

## Run it

Clone the repository, then run:

```bash
git clone https://github.com/aashleshshet/Scanx.git
cd Scanx
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

# Inspect parsed operations, parameters, security requirements and auth scheme locations.
api-sentry inspect --spec examples/openapi.yaml

# Exercise the complete pipeline with synthetic vulnerable and protected APIs.
python examples/demo.py --output-dir demo-reports/vulnerable
python examples/demo.py --protected --output-dir demo-reports/protected

pytest -q
ruff check .
ruff format --check .
```

For a real API, copy the example specification and scenario file and replace the seeded object IDs with your own test fixtures. Supply actual tokens through your secret manager or process environment, using the variable names in `scenarios.yaml`. Do not put tokens on the command line or commit them to source control.

```bash
api-sentry scan \
  --base-url https://api.example.test/api/v1 \
  --spec examples/openapi.yaml \
  --scenarios examples/scenarios.yaml \
  --output-dir reports \
  --fail-on High
```

The exact API root comes from `--base-url`. It preserves `/api/v1` and deliberately ignores spec `servers`, Swagger `host`, `schemes` and `basePath`. Do not duplicate that prefix in the spec paths. Redirects are returned as observations and never followed. Environment proxy settings are ignored; TLS certificate verification stays enabled.

Active injection and burst checks require both a CLI flag and selected fixture parameters/routes:

```bash
api-sentry scan \
  --base-url https://api.example.test/api/v1 \
  --spec examples/openapi.yaml \
  --scenarios examples/scenarios.yaml \
  --injection --timing --sql-dialect postgres \
  --rate-limit --concurrency 8 --max-requests 500 \
  --output-dir reports
```

`--injection` enables a syntax probe. `--timing` adds three interleaved control/probe pairs for each SQL and shell timing experiment, using a two-second delay. Timing checks run separately from ordinary checks. `--rate-limit` runs one successful control followed by exactly 50 rapid requests, bounded by `--concurrency`. This burst bypasses the normal `--rps` pacer and runs separately from all other tests. Requests are never retried, including HTTP 429 responses.

GET/HEAD/OPTIONS are the default executable methods. POST/PUT/PATCH/DELETE require `--allow-writes` plus an explicit request fixture; TRACE is inventoried but never executed. BOLA tests only GET object reads. A nominally safe HTTP method can still have application-specific side effects, so seed disposable fixtures. Timing payloads contain no file access, destructive SQL or external callbacks; they can consume resources or interact with application behavior.

Exit codes: `0` completed within the selected finding threshold; `1` a finding meets `--fail-on`; `2` invalid input, I/O failure or partial scan; `130` keyboard interrupt. Skipped and inconclusive outcomes are separately reported and should be reviewed even when the command exits `0`. A partial scan takes precedence over a finding threshold.

## Core engine and extension contract

Read `src/api_sentry/engine.py` and `src/api_sentry/transport.py` together. The engine dispatches a fixed number of endpoint workers; the transport owns one AsyncClient, a semaphore, normal request pacing, a global request budget, per-request deadlines and streamed response caps. This follows HTTPX's [async client](https://www.python-httpx.org/async/) and [transport](https://www.python-httpx.org/advanced/transports/) interfaces.

Every module implements:

```python
class Check(Protocol):
    name: str

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]: ...
```

Checks return typed results instead of printing or writing files. A transport error cannot become a vulnerability by itself. A scan deadline cancels unfinished work and reports explicit incomplete checks. Raw `httpx.Request` objects keep the client's accumulated cookie jar out of subsequent requests, preventing a response to User A from silently authenticating User B or an anonymous probe. Identity credentials are applied per request and never installed as global client headers.

## Complete BOLA experiment

`src/api_sentry/checks/bola.py` is the complete implementation. Its test oracle combines the intended access policy with response identity and stable representations:

1. Declare an A-owned private object and a B-owned private object. They must use different numeric IDs or UUIDs, and the identities must use different effective credentials.
2. Obtain an owner baseline for each object. Require success and an exact object identity match at a configured JSON Pointer such as `/id` or `/data/id`.
3. Require anonymous access to both objects to be denied with 401, 403 or 404. Public or ambiguous objects cannot produce a confirmed BOLA finding.
4. Request A's object as B, then B's object as A. Change only the selected path/query ID and the principal; preserve other fixture values.
5. To confirm disclosure, require success, the correct object identity and canonical JSON equality with the owner's complete response. Recheck the owner to ensure the representation is stable.
6. Report High severity with `verification: confirmed` for reproduced cross-user disclosure. Both cross-user denials produce a passed result. Other responses are inconclusive.

The `private_objects: true` scenario field is the operator's assertion that cross-user access is forbidden. The scanner cannot infer business ownership from an OpenAPI document. Use two principals with comparable roles in the intended test context, and fixtures with known ownership. This operationalizes [OWASP's BOLA guidance](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/): identifiers are inputs to authorization decisions; UUID unpredictability does not provide authorization.

The strict full-representation comparison intentionally favors precision. Dynamic fields, different but still sensitive projections, public summary fields and eventual consistency may need an application-specific oracle. An inconclusive result remains visible instead of becoming a false pass. Add explicit projection rules and negative controls only after you can test them against known vulnerable and protected cases.

## Specification and authentication handling

Supports OpenAPI 3.0.x/3.1.x and Swagger 2.0, JSON or YAML, path/operation parameters, scalar path/query/header/cookie values, JSON request bodies, local `$ref`s, and operation-level security overrides. Operation parameters override matching path parameters. Security requirements use OR between entries and AND within an entry; `security: []` and an empty alternative `{}` make authentication optional, per the [OpenAPI specification](https://spec.openapis.org/oas/v3.1).

The spec parser inventories methods, parameters, request-body metadata and authentication schemes. Runtime credentials come from environment-backed identities keyed by security scheme name. Bearer/OAuth2/OpenID tokens receive the `Bearer` prefix. Basic credentials use an environment value of `username:password` and are encoded for the header. API keys use the declared header, query or cookie location. OAuth scopes are inventoried; the scanner does not acquire/refresh tokens or independently validate granted scopes.

External references must be bundled before use; the parser never fetches them. YAML aliases, duplicate mapping keys and documents larger than 4 MiB are rejected, along with inputs over 100,000 nodes or 64 nesting levels. The transport requests identity encoding and rejects compressed responses without decoding them to keep the response cap meaningful. This normalizer is not a complete OpenAPI validator. OpenAPI 3.2, array/object parameter serializers, form/multipart bodies, Digest, mTLS and authentication flows are extension work. Required values without a fixture/default/example cause an explicit skip. The tool does not invent valid business data.

## Detection semantics and severity

| Check | Decision | Default severity / confidence |
|---|---|---|
| BOLA | Private cross-user object response matches owner baseline and recheck | High / high, confirmed |
| Authentication | Expected-protected anonymous JSON matches authenticated control | High / medium, needs review |
| Diagnostic disclosure | Recognizable stack trace signature | Medium / medium, needs review |
| Headers | Missing HTTPS HSTS; CSP/framing checks depend on rendered HTML | Low / high, needs review |
| CORS | Wildcard origin with credentials | Low / high, misconfiguration |
| CORS | Both untrusted synthetic origins reflected with credentials | Medium / medium, needs review |
| Injection | New DB/shell error signature or repeatable controlled timing difference | Medium / medium, needs review |
| Rate limiting | All 50 burst requests succeed without HTTP 429 | Low / low, inconclusive |

CSP and X-Frame-Options are recorded as missing on JSON routes but are not elevated to findings solely on that basis; their relevance depends on rendering context. A CSP `frame-ancestors` directive can satisfy the framing control. Header values are not comprehensively audited. See [OWASP's HTTP Headers guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

`Access-Control-Allow-Origin: *` plus `Access-Control-Allow-Credentials: true` is an invalid credentialed CORS configuration: browsers block access. It does not by itself demonstrate credentialed data theft. Reflection with credentials is a more relevant candidate and still needs a browser/cookie/preflight review. See [MDN's credentialed CORS explanation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials).

Absence of HTTP 429 in 50 requests does not prove absence of a rate limiter. Policies may use a larger window, a higher threshold or another limiting mechanism. Authentication absence on intentionally public routes is an observation, not a vulnerability. SQL/command injection are additional CWE-89/CWE-78 checks; injection is not a standalone category in the [OWASP API Top 10 2023](https://devguide.owasp.org/en/07-training-education/07-api-top-ten/). The API8 mapping is an approximate coverage association, not a claim that every injection issue is an API8-specific flaw.

The schema supports Critical, High, Medium and Low. Current heuristics do not automatically assign Critical; reserve that for validated business impact such as cross-tenant administrative takeover. Severity and confidence are independent.

## Reporting schema

`models.py` is the single source of truth for reports; `reporting.py` generates the JSON Schema and all three output formats. Generate it with:

```bash
api-sentry schema --output schemas/report.schema.json
```

```text
ScanReport
  schema_version, tool_version, scan_id
  started_at, finished_at                 # timezone-aware UTC timestamps
  target, spec_sha256
  status                                 # complete | partial
  modules, operations_discovered, operations_scheduled, requests_sent
  summary                                # Critical / High / Medium / Low counts
  checks[]
    module, operation
    status                               # passed | failed | inconclusive | skipped | error
    reason, observations
    findings[]
      id, rule_id, module, title
      severity, confidence, verification
      operation, description
      evidence                           # structured scalars/lists/maps; no raw bodies or tokens
      remediation, owasp[], cwe[]
  errors[], limitations[]
```

Findings are nested under the check that produced them, so provenance and coverage stay together. For consumers, flatten `checks[].findings[]`. Structured evidence uses status codes, timings and comparison outcomes; raw request URLs with identifiers/query tokens, response bodies and cookies are omitted. The report includes the configured API root and endpoint templates. Supply only nonsecret API roots/spec metadata and avoid secret literals in scenario data.

The writer additionally redacts supplied credential values, escapes all untrusted HTML/Markdown text, renders HTML with no remote dependencies or scripts, and atomically replaces each output file with permissions `0600`. Report contents still reveal target inventory and should be handled as assessment artifacts. The JSON Schema rejects unknown model fields. `summary` is derived from findings at scan completion; schema validation alone does not verify aggregate counts.

## Build order and next extensions

1. Run the demo, inspect JSON and read the BOLA test cases first.
2. Adapt `scenarios.yaml` to an API you control and validate protected and intentionally public controls.
3. Add API-specific response oracles for dynamic representations and alternate ownership fields.
4. Extend serializers with fixture-driven tests for arrays, nested JSON and body IDs.
5. Add authentication lifecycle support, configurable expected rate policies and policy-aware CI coverage thresholds.

Commit a resolved dependency lock for your chosen Python/platform and validate it in CI before releasing. The project specifies bounded dependency ranges; it does not claim a reproducible locked supply chain or complete OWASP Top 10 coverage. The included workflow runs lint, formatting and tests across Python 3.11–3.13; execution in this workspace is documented separately in `VALIDATION.md`.
