# Roadmap and explicit boundaries

Implemented MVP: current scanner preserved, ten workspace destinations plus the beginner guide, JSON endpoint inventory, approved ownership-verified worker jobs, single-operator sessions, SQL-backed reports/audit/schedules, Redis/Celery, evidence retrieval and optional provider synthesis, PDF/CSV/JSON, public GitHub spec import, device saves, historical comparisons, Docker configuration and CI checks.

Next work, not represented as shipped functionality:

1. Deploy managed PostgreSQL/Redis and container services, verify real TLS/egress/network policy, configure a provider and run model-specific adversarial evaluations. Current Vercel deployment has no backend or LLM credentials configured.
2. Robust job leases, transactional scheduling/outbox, idempotent retries, cancellation, retention, pagination and operational metrics before scaling workers.
3. Normalized versioned database migrations, organization membership, RBAC and tenant-isolation tests before offering a multi-customer service.
4. OWASP ZAP passive analysis adapter with scope enforcement and evidence normalization. ZAP is not installed or invoked in this MVP; custom checks are the working scanner.
5. Private GitHub App integration with repo-scoped access; browser YAML parsing; authenticated API specification revisions.
6. Vector retrieval and historical context synthesis with source versioning, evaluation datasets and token/cost budgets. Current retrieval uses deterministic lexical ranking, not embeddings.
7. Provider response evaluation beyond citation membership; valid citations alone cannot guarantee factual summaries. Retain human review and never create verified findings from generated text.
8. Full physical-device/screen-reader coverage, automated visual regressions, PDF typography/font embedding, and release gates connecting CI to Vercel production promotion.

Shipping a configurable single-operator MVP does not establish enterprise production readiness. The repository documents working behavior separately from external infrastructure and future features.
