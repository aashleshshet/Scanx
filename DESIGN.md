# OnescanX Liquid Glass design system

Existing product and routes remain: Overview, Findings, Scan history, How to use, beginner guide, copyright, local scan configuration, and self-contained reports. Hosted authentication remains Vercel Deployment Protection. An optional SQL-backed single-operator platform extends the browser workspace. Disconnected states are explicit; optional device storage requires user action.

## Tokens and surfaces

The shared stylesheet defines navy/charcoal ground, cyan primary accents, controlled violet ambient light, semantic severity colors, glass opacity, highlight, border, shadow, radius, blur, and timing tokens. Light appearance overrides the same tokens. `theme.js` loads before CSS, follows OS appearance until overridden, and stores only that preference.

Blur is limited to outer panels. Nested controls use fills, and touch/reduced-transparency devices use solid translucent fallback panels without blur. Ambient lighting is static. Motion uses short transforms/opacity for hover, press, and dialog entry. Scan progress is indeterminate, never an invented completion percentage. Reduced motion removes animation.

The mobile layout provides labeled bottom navigation, safe-area spacing, stacked finding rows, 44px primary/form targets, and accessible native dialogs. The tablet breakpoint simplifies columns and keeps controls usable. Severity, source, and verification remain textual as well as colored.

Portfolio badge markup, placeholder profile styles, and its JS dependency are removed. The actual OnescanX brand and all scan/report contracts remain intact. No new frontend runtime dependencies; Playwright and axe are development-only test dependencies.

## Intelligence workspace extension

The existing palette, mark, type and glass tokens carry into inventory, worker configuration, analytics, evidence retrieval, reports, integrations and settings. Report-derived views retain the source banner so synthetic results remain identifiable. Severity bars render actual counts; historical comparison uses rule/operation/verification keys with an explicit coverage caveat. Mobile navigation presents four primary routes and a More command menu rather than eleven narrow tabs. Worker progress uses actual queue states, never invented percentages.
