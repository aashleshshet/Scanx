import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { assetName } from '../../../lib/access.mjs';
export const dynamic = 'force-dynamic';
const headers = { 'Cache-Control': 'private, no-store, max-age=0', 'Vary': 'Cookie', 'X-Content-Type-Options': 'nosniff' };
export async function GET(request, context) {
  // Vercel Deployment Protection authenticates hosted requests before this handler.
  const parts = (await context.params).path;
  if (!parts?.length) return new Response(null, { status: 303, headers: { ...headers, Location: '/workspace/index.html' } });
  const name = assetName(parts);
  if (!name) return new Response('Not found', { status: 404, headers });
  // Fixed directory plus a single allowlisted filename; never serve arbitrary repository files.
  let data;
  try { data = await readFile(join(process.cwd(), 'src/api_sentry/web/static', name)); }
  catch { return new Response('Not found', { status: 404, headers }); }
  const types = { html: 'text/html', css: 'text/css', js: 'text/javascript', json: 'application/json', yaml: 'text/plain', svg: 'image/svg+xml' };
  return new Response(data, { headers: { ...headers, 'Content-Type': `${types[name.split('.').pop()]}; charset=utf-8` } });
}
