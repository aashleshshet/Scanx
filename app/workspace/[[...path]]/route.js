import { auth, currentUser } from '@clerk/nextjs/server';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { verifiedEmail, assetName } from '../../../lib/access.mjs';
export const dynamic = 'force-dynamic';
const headers = { 'Cache-Control': 'private, no-store, max-age=0', 'Vary': 'Cookie', 'X-Content-Type-Options': 'nosniff' };
export async function GET(request, context) {
  const { userId } = await auth();
  if (!userId) return new Response(null, { status: 303, headers: { ...headers, Location: '/sign-in' } });
  const user = await currentUser();
  if (!verifiedEmail(user)) return new Response(null, { status: 303, headers: { ...headers, Location: '/account' } });
  const parts = (await context.params).path;
  if (!parts?.length) return new Response(null, { status: 303, headers: { ...headers, Location: '/workspace/index.html' } });
  const name = assetName(parts);
  if (!name) return new Response('Not found', { status: 404, headers });
  // Fixed directory plus a single allowlisted filename; never serve arbitrary repository files.
  let data;
  try { data = await readFile(join(process.cwd(), 'src/api_sentry/web/static', name)); }
  catch { return new Response('Not found', { status: 404, headers }); }
  if (name === 'index.html') {
    data = data.toString().replace('<div class="top-actions">', '<div class="top-actions"><a href="/account">Account / sign out</a>');
  }
  const types = { html: 'text/html', css: 'text/css', js: 'text/javascript', json: 'application/json', yaml: 'text/plain', svg: 'image/svg+xml' };
  return new Response(data, { headers: { ...headers, 'Content-Type': `${types[name.split('.').pop()]}; charset=utf-8` } });
}
