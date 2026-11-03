import { clerkMiddleware } from '@clerk/nextjs/server';
export default clerkMiddleware();
// Include extensions: HTML/JSON report routes require the same session as pages.
export const config = { matcher: ['/((?!_next/).*)'] };
