# Hosted workspace with Vercel login

Production: https://onescanx.vercel.app

The Next.js application serves the shared OnescanX Liquid Glass, mobile-responsive frontend at `/workspace/index.html`. **Vercel Deployment Protection remains the website login.** Keep Vercel Authentication enabled for every domain serving this app. The current `all_except_custom_domains` policy protects its Vercel URLs; explicitly protect any custom domain before adding it. Do not turn protection off: the frontend intentionally contains no second website login gate. The optional backend has its own operator session for data and scanning APIs.

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

The dashboard and direct report assets use private/no-store responses. Asset filenames are restricted to prevent arbitrary file access. Imported reports remain in browser-tab memory unless explicitly saved on the device or connected platform; export JSON to preserve an assessment. The Python scanner remains a separate local tool (`scanx-web`). The optional platform bridge is dormant until an HTTPS backend and bridge key are configured; it then forwards only authenticated, approved-scope jobs. See [platform setup](platform/INSTALL.md).

## Git integration

The existing Vercel project now deploys `aashleshshet/Scanx` main through its Git integration. After pushing, inspect the deployment for the exact commit and monitor it; do not create a duplicate manual deployment. The source-file API remains a fallback only if no Git deployment is triggered.

Android packaging and the APK have been removed from the current branch. Historical commits retain their previous contents.
