# Platform API v1

Prefix `/api/platform`. JSON bodies, maximum 2 MB; validation errors do not echo submitted values. All routes except login require an operator session. The fixed Next.js bridge has the same paths; `/status` reports `{ "connected": false }` when no backend is configured. Errors use `{ "detail": "safe message" }`.

| Method and path | Input / response |
| --- | --- |
| POST `/session/login` | `{password}` → `{authenticated:true}` plus scoped HttpOnly cookie |
| POST `/session/logout` | Revokes current session and cookie |
| GET `/status` | connected, workspace, approved targets, AI/worker configuration flags |
| GET `/inventory` | Latest assets, without specification, scenarios or ownership token |
| POST `/inventory` | `{name,target,spec,scenarios?}` → `{id,challenge,instructions}`; spec/scenarios are document strings |
| POST `/inventory/{id}/verify` | Checks public ownership token; returns `verified_until` (Unix seconds) |
| POST `/inventory/{id}/scan` | 202 `{id,status:"queued"}` after approval/ownership checks |
| GET `/jobs` | Job IDs, asset IDs, statuses, report IDs/safe errors |
| GET `/reports` | Report IDs, targets, finish times and severity summaries |
| POST `/reports` | Complete `ScanReport` schema 1.0.0 → `{id}` |
| GET `/reports/{id}` | Complete original report with recomputed summary |
| GET `/reports/{id}/export/{pdf,csv,json}` | Attachment; format-specific content type |
| POST `/reports/{id}/assistant` | `{question,consent:false}` → evidence or advisory synthesis contract below |
| GET `/schedules` | Schedule IDs, asset IDs, interval, next run |
| POST `/schedules` | `{asset_id,interval_hours}` (1–8760) → `{id}` |
| DELETE `/schedules/{id}` | `{deleted:true}`; no future runs |
| GET `/audit` | Action-only audit records, newest first |

`GET /health` is a public liveness endpoint, not database/worker readiness. Run a real authenticated status/report request to verify the complete backend connection.

Assistant response:

```json
{
  "mode": "evidence",
  "advisory": true,
  "summary": "Retrieved scanner observations; no model inference was performed.",
  "citations": ["original-finding-id"],
  "evidence": [{
    "id": "original-finding-id",
    "title": "Original scanner observation",
    "operation": "GET /objects/{id}",
    "severity": "High",
    "confidence": "high",
    "verification": "confirmed",
    "remediation": "Original remediation guidance",
    "owasp": ["API1:2023"]
  }],
  "guidance": {"API1:2023": "Enforce ownership and tenant checks for every object lookup."}
}
```

The example describes a response shape, not a live finding. `mode="llm"` requires both configuration and explicit consent. Unknown/absent citation IDs reject the model response with 502. Scanner verification state is never promoted by the model.

Next.js-only integration: `GET /api/integrations/github?repo=owner/name&path=openapi.json&ref=main` returns `{content,sha}` for a public JSON/YAML file under 1 MB. Host is fixed to GitHub; repo/path/ref are validated, redirects rejected, and no user token accepted. Browser inventory currently parses JSON; use the Python parser for YAML. The returned SHA is a **file blob** SHA, not a repository commit. GitHub rate limits apply.
