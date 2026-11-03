# Hosted workspace with Vercel login

Production: https://onescanx.vercel.app

The Next.js application serves the shared OnescanX dark, mobile-responsive frontend at `/workspace/index.html`. **Vercel Deployment Protection is the only authentication layer.** Keep Vercel Authentication enabled for every domain serving this app. The current `all_except_custom_domains` policy protects its Vercel URLs; explicitly protect any custom domain before adding it. Do not turn protection off: the application intentionally contains no second login gate.

Vercel decides which accounts may access the project. This is not open registration for anyone with a verified email. Manage visitor access in Vercel. Clerk is no longer used: its package, provider, middleware, email checks, and sign-in/sign-up/account screens have been removed. Existing Clerk integration resources or credentials are not consumed by the app; remove the integration separately if it is no longer needed by any project.

## Build and develop

Use Node 22+ and pnpm 10.11.0:

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm build
pnpm dev
```

No application authentication keys are required. Local development is unauthenticated and intended for the operator's machine. Deploy using the Next.js framework preset with `pnpm build`. Never publish the frontend or deploy this app to an unprotected host when authentication is required.

The dashboard and direct report assets use private/no-store responses. Asset filenames are restricted to prevent arbitrary file access. Imported reports remain in browser-tab memory; export JSON to preserve an assessment. The Python scanner remains a separate local tool (`scanx-web`); no public scanning proxy is deployed.

## Git integration

Deployment currently uses Vercel's source-file API because its GitHub App has not been authorized for this repository. GitHub holds the matching source. Install the Vercel GitHub App for `aashleshshet/Scanx` and connect it in project Git settings to enable automatic deployments. A GitHub login connection alone does not grant repository access.

Android packaging and the APK have been removed from the current branch. Historical commits retain their previous contents.
