import { type NextRequest, NextResponse } from "next/server";

import { getAccessToken } from "@/lib/session";
import { apiUrl, proxySecret } from "@/lib/server-env";
import { buildUpstreamUrl, upstreamHeaders } from "@/lib/upstream";

// Browser -> Next.js -> FastAPI (PRD §3.2 Vercel row). Adds the access token and the shared
// proxy secret server-side; the browser only sends its session cookie.

const MAX_BODY_BYTES = 64 * 1024;

type Ctx = { params: Promise<{ path: string[] }> };

function json(status: number, detail: string): NextResponse {
  return NextResponse.json({ detail }, { status });
}

async function forward(request: NextRequest, ctx: Ctx): Promise<NextResponse> {
  const { path } = await ctx.params;
  const url = buildUpstreamUrl(apiUrl(), path, request.nextUrl.search);
  if (!url) return json(400, "bad path");
  const token = await getAccessToken();
  if (!token) return json(401, "not signed in");

  const init: RequestInit = {
    method: request.method,
    headers: upstreamHeaders(request.headers, token, proxySecret()),
    cache: "no-store",
    redirect: "manual",
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    const body = await request.text();
    if (new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES) return json(413, "body too large");
    init.body = body;
  }

  let upstream: Response;
  try {
    upstream = await fetch(url, init);
  } catch {
    return json(502, "api unreachable");
  }
  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: { "content-type": upstream.headers.get("content-type") ?? "application/json" },
  });
}

export { forward as DELETE, forward as GET, forward as PATCH, forward as POST, forward as PUT };
