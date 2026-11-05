// Same-origin bridge: a fixed operator-configured backend, never a client-provided URL.
export const dynamic = "force-dynamic";
const allowed =
  /^(status|inventory(?:\/[a-zA-Z0-9-]+(?:\/(verify|scan))?)?|jobs|reports(?:\/[a-zA-Z0-9-]+(?:\/(assistant|export\/(pdf|csv|json)))?)?|schedules(?:\/[a-zA-Z0-9-]+)?|audit|session\/(login|logout))$/;
async function bridge(request, context) {
  const path = ((await context.params).path || []).join("/");
  if (!allowed.test(path))
    return Response.json({ detail: "Not found" }, { status: 404 });
  if (
    request.method !== "GET" &&
    request.headers.get("origin") !== new URL(request.url).origin
  )
    return Response.json(
      { detail: "Same-origin request required" },
      { status: 403 },
    );
  const base = process.env.ONESCANX_BACKEND_URL;
  const key = process.env.ONESCANX_BRIDGE_KEY;
  if ((!base || !key) && path === "status")
    return Response.json(
      { connected: false },
      { headers: { "Cache-Control": "no-store" } },
    );
  if (!base || !key)
    return Response.json(
      {
        detail:
          "Platform backend is not connected. Use Docker setup or configure the existing project connection.",
      },
      { status: 503 },
    );
  try {
    const target = new URL(base);
    if (
      target.protocol !== "https:" ||
      target.username ||
      target.password ||
      target.search ||
      target.hash
    )
      throw Error("config");
    const reader = request.body?.getReader();
    const chunks = [];
    let size = 0;
    if (reader)
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 2_000_000) {
          await reader.cancel();
          return Response.json(
            { detail: "Request too large" },
            { status: 413 },
          );
        }
        chunks.push(value);
      }
    const body = size ? Buffer.concat(chunks) : undefined;
    const sessionCookie = (request.headers.get("cookie") || "")
      .split(";")
      .map((part) => part.trim())
      .find((part) => /^onescanx_session=[A-Za-z0-9_-]{20,128}$/.test(part)) || "";
    const response = await fetch(
      `${base.replace(/\/$/, "")}/api/platform/${path}`,
      {
        method: request.method,
        body,
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(35000),
        headers: {
          "Content-Type": "application/json",
          "x-onescanx-bridge": key,
          Cookie: sessionCookie,
        },
      },
    );
    const headers = new Headers({
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
    });
    for (const name of ["content-type", "content-disposition", "set-cookie"]) {
      const value = response.headers.get(name);
      if (value) headers.set(name, value);
    }
    return new Response(response.body, { status: response.status, headers });
  } catch {
    return Response.json(
      { detail: "Platform backend is unavailable" },
      { status: 502 },
    );
  }
}
export const GET = bridge,
  POST = bridge,
  DELETE = bridge;
