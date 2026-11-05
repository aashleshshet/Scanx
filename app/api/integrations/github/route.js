export const dynamic = "force-dynamic";
export async function GET(request) {
  const query = new URL(request.url).searchParams;
  const repo = query.get("repo") || "",
    path = query.get("path") || "",
    ref = query.get("ref") || "main";
  if (
    !/^[\w.-]+\/[\w.-]+$/.test(repo) ||
    !/^[-\w./]+\.(json|ya?ml)$/.test(path) ||
    path.split("/").includes("..") ||
    !/^[-\w.]+$/.test(ref)
  )
    return Response.json(
      { detail: "Enter owner/repository, a JSON/YAML file path, and branch." },
      { status: 400 },
    );
  try {
    const response = await fetch(
      `https://api.github.com/repos/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`,
      {
        headers: { Accept: "application/vnd.github+json" },
        redirect: "error",
        signal: AbortSignal.timeout(10000),
        cache: "no-store",
      },
    );
    if (!response.ok)
      return Response.json(
        {
          detail:
            "Public repository file unavailable or GitHub rate limit reached.",
        },
        { status: response.status === 404 ? 404 : 502 },
      );
    const raw = await response.text();
    if (raw.length > 1_500_000) throw Error("size");
    const data = JSON.parse(raw);
    if (
      data.type !== "file" ||
      data.encoding !== "base64" ||
      data.size > 1_000_000
    )
      throw Error("file");
    return Response.json(
      {
        content: Buffer.from(data.content, "base64").toString("utf8"),
        sha: data.sha,
        repo,
        path,
        ref,
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return Response.json(
      { detail: "Could not retrieve the specification." },
      { status: 502 },
    );
  }
}
