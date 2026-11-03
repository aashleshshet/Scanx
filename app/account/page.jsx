import { UserButton, UserProfile } from '@clerk/nextjs';
import { auth } from '@clerk/nextjs/server';
export default async function Account() { const { userId, redirectToSignIn } = await auth(); if (!userId) return redirectToSignIn(); return <main className="account"><header><a href="/workspace/index.html">← Workspace</a><UserButton /></header><h1>Your account</h1><p>Verify your primary email address to access Scanx. Use the profile menu to sign out.</p><UserProfile routing="hash" /></main>; }
