# API Security Assessment

**Target:** https://synthetic\-api\.invalid

**Scan:** 6e9e9140\-708a\-4927\-aa13\-a3505110f5a9  
**Status:** complete  
**Finished (UTC):** 2026\-11\-02T14:26:47\.323820Z

## Executive assessment

The configured scan produced **0 findings** across **3 operations** using **73 requests**. Prioritize confirmed authorization failures, then validate candidate findings. Severity describes impact; confidence describes the strength of automated evidence.

| Severity | Findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

## Coverage

passed: 12, skipped: 6

Skipped and inconclusive checks are coverage gaps, not passes.

## Findings

No findings were produced by completed configured checks.

## Check outcomes

| Operation | Module | Status | Reason |
|---|---|---|---|
| GET /health | auth | passed | Public route behavior inventoried; authentication is not required by policy |
| GET /health | bola | skipped | BOLA needs a GET operation and explicit private\-object fixtures |
| GET /health | cors | passed | No tested credentialed\-origin misconfiguration observed |
| GET /health | headers | passed | Header presence and diagnostic disclosure checked |
| GET /health | injection | skipped | Select injection\_parameters in the request fixture |
| GET /health | rate\_limit | skipped | Enable rate\_limit for an explicit request fixture |
| GET /orders/\{order\_id\} | auth | passed | Authenticated control succeeded; anonymous read denied |
| GET /orders/\{order\_id\} | bola | passed | Both configured cross\-user reads were denied |
| GET /orders/\{order\_id\} | cors | passed | No tested credentialed\-origin misconfiguration observed |
| GET /orders/\{order\_id\} | headers | passed | Header presence and diagnostic disclosure checked |
| GET /orders/\{order\_id\} | injection | skipped | Select injection\_parameters in the request fixture |
| GET /orders/\{order\_id\} | rate\_limit | skipped | Enable rate\_limit for an explicit request fixture |
| GET /search | auth | passed | Authenticated control succeeded; anonymous read denied |
| GET /search | bola | skipped | BOLA needs a GET operation and explicit private\-object fixtures |
| GET /search | cors | passed | No tested credentialed\-origin misconfiguration observed |
| GET /search | headers | passed | Header presence and diagnostic disclosure checked |
| GET /search | injection | passed | No configured injection signal was observed |
| GET /search | rate\_limit | passed | HTTP 429 throttling observed in the tested burst |

## Limitations

- DEMONSTRATION: all responses are synthetic in\-process fixtures; no live API was scanned\.
- Automated checks cover selected risks, not the entire OWASP API Top 10\.
- Passed means the configured test observed expected behavior; it is not a security guarantee\.
- BOLA coverage is limited to declared private fixtures and GET object reads\.
- A 50\-request burst cannot establish the absence of all rate limits\.
- Timing and syntax findings need manual validation; database dialects vary\.
