# Hosted verified-email workspace

The Next.js application serves the shared liquid-glass frontend at `/workspace/index.html`. Clerk manages sign-up, email verification, sessions, and sign-out. Any account with a **verified primary email** can access the workspace; there is no email allowlist. Both session and primary-email verification are checked on the server for every workspace asset, including HTML and JSON. Responses are private/no-store. Files are read only from the shared frontend directory using a restricted filename policy.

## Vercel setup

Project: `scanx`, team: `aashlesh-ramadas-shet`. Install the Clerk integration and connect its resource to the project. Required variables for Preview and Production:

- `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`
- `CLERK_SECRET_KEY`

In Clerk, enable email sign-up/sign-in and require email verification. Enable email-code authentication if passwordless login is desired. Disable social providers and phone authentication if the UI should offer email only. The server independently rejects accounts without a verified primary email, regardless of enabled provider options. Production Clerk instances may require domain configuration in the Clerk dashboard.

Deploy using Node 22, `pnpm install --frozen-lockfile`, and `pnpm build`. The project has application authentication; Vercel account authentication must not be required for production visitors. Never publish shared frontend assets separately as a public static directory when authentication is required.

## Local development

Use Node 22+ and pnpm 10.11.0. Copy `.env.example` to `.env.local` and populate it securely with your Clerk development credentials. Then run `pnpm install`, `pnpm test`, and `pnpm dev`. No authentication keys belong in Git. `pnpm build` verifies the production bundle.

Account controls and sign-out are available at `/account`, linked from the dashboard. Imported reports stay in the current browser tab; the app does not store them in Clerk or upload them to Vercel. Closing or navigating away from the dashboard clears that in-memory view. Export JSON first to preserve it.

The Python scanner remains a separate local tool (`scanx-web`). No public scanning API or arbitrary target proxy is deployed on Vercel.

## Repository connection

Initial deployment uses the source-file API because Vercel's GitHub App was not yet authorized for this repository. The GitHub repository contains the matching source. For automatic deployments, install the Vercel GitHub App for `aashleshshet/Scanx` and connect it in the project's Git settings. Connecting GitHub as a login method alone does not grant repository deployment access.

The Android APK and packaging have been removed from the current branch. Older commits retain their historical contents.
