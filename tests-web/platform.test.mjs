import test from "node:test";
import assert from "node:assert/strict";
import { GET, POST } from "../app/api/platform/[[...path]]/route.js";
import { GET as github } from "../app/api/integrations/github/route.js";

test("bridge forwards only the platform session, never Vercel or other cookies", async () => {
  const originalFetch = globalThis.fetch;
  const originalURL = process.env.ONESCANX_BACKEND_URL;
  const originalKey = process.env.ONESCANX_BRIDGE_KEY;
  process.env.ONESCANX_BACKEND_URL = "https://backend.example";
  process.env.ONESCANX_BRIDGE_KEY = "test-only-bridge";
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "https://backend.example/api/platform/status");
    assert.equal(options.headers.Cookie, "onescanx_session=fixture-token-with-enough-characters");
    assert.equal(options.redirect, "error");
    return Response.json({connected:true});
  };
  try {
    const request = new Request("https://site.example/api/platform/status", {
      headers: {cookie:"vercel_protection=private; onescanx_session=fixture-token-with-enough-characters; other=private"},
    });
    const response = await GET(request, {params:Promise.resolve({path:["status"]})});
    assert.equal(response.status,200);
    assert.equal((await response.json()).connected,true);
  } finally {
    globalThis.fetch = originalFetch;
    if(originalURL === undefined) delete process.env.ONESCANX_BACKEND_URL;
    else process.env.ONESCANX_BACKEND_URL = originalURL;
    if(originalKey === undefined) delete process.env.ONESCANX_BRIDGE_KEY;
    else process.env.ONESCANX_BRIDGE_KEY = originalKey;
  }
});

test("disconnected bridge is explicit and blocks unsafe origins and paths", async () => {
  const params = (path) => ({ params: Promise.resolve({ path }) });
  const status = await GET(
    new Request("https://onescanx.example/api/platform/status"),
    params(["status"]),
  );
  assert.deepEqual(await status.json(), { connected: false });
  assert.equal(
    (
      await GET(
        new Request("https://onescanx.example/api/platform/secrets"),
        params(["secrets"]),
      )
    ).status,
    404,
  );
  assert.equal(
    (
      await POST(
        new Request("https://onescanx.example/api/platform/session/login", {
          method: "POST",
        }),
        params(["session", "login"]),
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await POST(
        new Request("https://onescanx.example/api/platform/session/login", {
          method: "POST",
          headers: { origin: "https://onescanx.example" },
        }),
        params(["session", "login"]),
      )
    ).status,
    503,
  );
});

test("GitHub importer rejects traversal, arbitrary hosts, and non-spec files", async () => {
  for (const query of [
    "repo=https://evil.example&path=a.json",
    "repo=owner/repo&path=../secret.json",
    "repo=owner/repo&path=private.env",
  ]) {
    assert.equal(
      (
        await github(
          new Request(
            "https://onescanx.example/api/integrations/github?" + query,
          ),
        )
      ).status,
      400,
    );
  }
});
