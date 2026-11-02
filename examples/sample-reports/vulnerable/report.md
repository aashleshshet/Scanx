# API Security Assessment

**Target:** https://synthetic\-api\.invalid

**Scan:** adccf34c\-6d12\-4e74\-8064\-66a63854e169  
**Status:** complete  
**Finished (UTC):** 2026\-11\-02T14:26:47\.345677Z

## Executive assessment

The configured scan produced **10 findings** across **3 operations** using **75 requests**. Prioritize confirmed authorization failures, then validate candidate findings. Severity describes impact; confidence describes the strength of automated evidence.

| Severity | Findings |
|---|---:|
| Critical | 0 |
| High | 2 |
| Medium | 1 |
| Low | 7 |

## Coverage

failed: 8, inconclusive: 1, passed: 3, skipped: 6

Skipped and inconclusive checks are coverage gaps, not passes.

## Findings

### High: Cross\-user access to a private object

**Operation:** GET /orders/\{order\_id\}  
**Rule:** BOLA\-001  
**Confidence:** high; **Verification:** confirmed

A different authenticated principal received the owner&\#x27;s complete JSON representation of an explicitly declared private object\.

**Remediation:** Authorize each object lookup against the authenticated principal and tenant\. Enforce ownership/ACL policy in the data\-access layer; add cross\-user regression tests\. UUIDs do not replace authorization\.

**Mapping:** API1:2023, CWE\-639

**Evidence:**

    {
      "direction": "B_accesses_A",
      "parameter_location": "path",
      "parameter_name": "order_id",
      "owner_status": 200,
      "cross_user_status": 200,
      "identity_marker_matches": true,
      "owner_recheck_matches": true,
      "representations_equal": true,
      "anonymous_statuses": [
        401,
        401
      ]
    }

### High: Cross\-user access to a private object

**Operation:** GET /orders/\{order\_id\}  
**Rule:** BOLA\-001  
**Confidence:** high; **Verification:** confirmed

A different authenticated principal received the owner&\#x27;s complete JSON representation of an explicitly declared private object\.

**Remediation:** Authorize each object lookup against the authenticated principal and tenant\. Enforce ownership/ACL policy in the data\-access layer; add cross\-user regression tests\. UUIDs do not replace authorization\.

**Mapping:** API1:2023, CWE\-639

**Evidence:**

    {
      "direction": "A_accesses_B",
      "parameter_location": "path",
      "parameter_name": "order_id",
      "owner_status": 200,
      "cross_user_status": 200,
      "identity_marker_matches": true,
      "owner_recheck_matches": true,
      "representations_equal": true,
      "anonymous_statuses": [
        401,
        401
      ]
    }

### Medium: Possible sql injection \(syntax signal\)

**Operation:** GET /search  
**Rule:** INJECTION\-SQL\-SYNTAX  
**Confidence:** medium; **Verification:** needs\_review

A controlled payload introduced a diagnostic or repeatable delay absent from control requests\. This is a candidate finding, not proof of arbitrary execution\.

**Remediation:** Use parameterized queries and bind variables; avoid SQL string concatenation\.

**Mapping:** API8:2023, CWE\-89

**Evidence:**

    {
      "parameter_name": "q",
      "probe_kind": "syntax",
      "new_error_signature": true,
      "baseline_status": 200,
      "probe_status": 500
    }

### Low: Wildcard origin with credentials

**Operation:** GET /health  
**Rule:** CORS\-001  
**Confidence:** high; **Verification:** needs\_review

Access\-Control\-Allow\-Origin: \* combined with credentials is an invalid credentialed CORS policy; browsers block credentialed response access\.

**Remediation:** Use an explicit trusted\-origin allowlist and Vary: Origin\. Enable credentialed CORS only when required\. Never reflect arbitrary Origin values\.

**Mapping:** API8:2023, CWE\-942

**Evidence:**

    {
      "wildcard_with_credentials": true,
      "two_origins_reflected_with_credentials": false
    }

### Low: Applicable browser security headers missing

**Operation:** GET /health  
**Rule:** HEADERS\-001  
**Confidence:** high; **Verification:** needs\_review

Response lacks one or more defense\-in\-depth headers relevant to its context\.

**Remediation:** Set HSTS on HTTPS responses after validating HTTPS coverage\. For rendered HTML, deploy a restrictive CSP including frame\-ancestors; use X\-Frame\-Options where legacy compatibility is needed\.

**Mapping:** API8:2023, CWE\-693

**Evidence:**

    {
      "missing_applicable_headers": [
        "Strict-Transport-Security"
      ],
      "html_response": false
    }

### Low: Wildcard origin with credentials

**Operation:** GET /orders/\{order\_id\}  
**Rule:** CORS\-001  
**Confidence:** high; **Verification:** needs\_review

Access\-Control\-Allow\-Origin: \* combined with credentials is an invalid credentialed CORS policy; browsers block credentialed response access\.

**Remediation:** Use an explicit trusted\-origin allowlist and Vary: Origin\. Enable credentialed CORS only when required\. Never reflect arbitrary Origin values\.

**Mapping:** API8:2023, CWE\-942

**Evidence:**

    {
      "wildcard_with_credentials": true,
      "two_origins_reflected_with_credentials": false
    }

### Low: Applicable browser security headers missing

**Operation:** GET /orders/\{order\_id\}  
**Rule:** HEADERS\-001  
**Confidence:** high; **Verification:** needs\_review

Response lacks one or more defense\-in\-depth headers relevant to its context\.

**Remediation:** Set HSTS on HTTPS responses after validating HTTPS coverage\. For rendered HTML, deploy a restrictive CSP including frame\-ancestors; use X\-Frame\-Options where legacy compatibility is needed\.

**Mapping:** API8:2023, CWE\-693

**Evidence:**

    {
      "missing_applicable_headers": [
        "Strict-Transport-Security"
      ],
      "html_response": false
    }

### Low: Wildcard origin with credentials

**Operation:** GET /search  
**Rule:** CORS\-001  
**Confidence:** high; **Verification:** needs\_review

Access\-Control\-Allow\-Origin: \* combined with credentials is an invalid credentialed CORS policy; browsers block credentialed response access\.

**Remediation:** Use an explicit trusted\-origin allowlist and Vary: Origin\. Enable credentialed CORS only when required\. Never reflect arbitrary Origin values\.

**Mapping:** API8:2023, CWE\-942

**Evidence:**

    {
      "wildcard_with_credentials": true,
      "two_origins_reflected_with_credentials": false
    }

### Low: Applicable browser security headers missing

**Operation:** GET /search  
**Rule:** HEADERS\-001  
**Confidence:** high; **Verification:** needs\_review

Response lacks one or more defense\-in\-depth headers relevant to its context\.

**Remediation:** Set HSTS on HTTPS responses after validating HTTPS coverage\. For rendered HTML, deploy a restrictive CSP including frame\-ancestors; use X\-Frame\-Options where legacy compatibility is needed\.

**Mapping:** API8:2023, CWE\-693

**Evidence:**

    {
      "missing_applicable_headers": [
        "Strict-Transport-Security"
      ],
      "html_response": false
    }

### Low: No rate limit observed in a 50\-request burst

**Operation:** GET /search  
**Rule:** RATE\-001  
**Confidence:** low; **Verification:** needs\_review

All 50 requests succeeded\. A higher threshold, longer time window, other limiting mechanism, or intentional policy can explain this result\.

**Remediation:** Define per\-principal and per\-route quotas, bounded resource consumption, and observable throttling\. Validate the documented thresholds in staging\.

**Mapping:** API4:2023, CWE\-770

**Evidence:**

    {
      "burst_size": 50,
      "http_429_count": 0,
      "successful": 50,
      "errors": 0,
      "max_concurrency": 8
    }

## Check outcomes

| Operation | Module | Status | Reason |
|---|---|---|---|
| GET /health | auth | passed | Public route behavior inventoried; authentication is not required by policy |
| GET /health | bola | skipped | BOLA needs a GET operation and explicit private\-object fixtures |
| GET /health | cors | failed | CORS policy needs review |
| GET /health | headers | failed | Header presence and diagnostic disclosure checked |
| GET /health | injection | skipped | Select injection\_parameters in the request fixture |
| GET /health | rate\_limit | skipped | Enable rate\_limit for an explicit request fixture |
| GET /orders/\{order\_id\} | auth | passed | Authenticated control succeeded; anonymous read denied |
| GET /orders/\{order\_id\} | bola | failed | Private object disclosure reproduced across principals |
| GET /orders/\{order\_id\} | cors | failed | CORS policy needs review |
| GET /orders/\{order\_id\} | headers | failed | Header presence and diagnostic disclosure checked |
| GET /orders/\{order\_id\} | injection | skipped | Select injection\_parameters in the request fixture |
| GET /orders/\{order\_id\} | rate\_limit | skipped | Enable rate\_limit for an explicit request fixture |
| GET /search | auth | passed | Authenticated control succeeded; anonymous read denied |
| GET /search | bola | skipped | BOLA needs a GET operation and explicit private\-object fixtures |
| GET /search | cors | failed | CORS policy needs review |
| GET /search | headers | failed | Header presence and diagnostic disclosure checked |
| GET /search | injection | failed | Injection signals need manual validation |
| GET /search | rate\_limit | inconclusive | No throttling observed within this 50\-request window |

## Limitations

- DEMONSTRATION: all responses are synthetic in\-process fixtures; no live API was scanned\.
- Automated checks cover selected risks, not the entire OWASP API Top 10\.
- Passed means the configured test observed expected behavior; it is not a security guarantee\.
- BOLA coverage is limited to declared private fixtures and GET object reads\.
- A 50\-request burst cannot establish the absence of all rate limits\.
- Timing and syntax findings need manual validation; database dialects vary\.
