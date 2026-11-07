// Next.js -> FastAPI forwarding rules (PRD §3.2 Vercel row, §8.5, §15.1).
// The browser never talks to FastAPI: it sends its session cookie to Next.js, and the server
// side attaches the access token and the shared proxy secret. Cookies are never forwarded.

const SAFE_SEGMENT = /^[A-Za-z0-9_-]{1,128}$/;

export function buildUpstreamUrl(base: string, segments: readonly string[], search: string): string | null {
  if (segments.length === 0 || !segments.every((s) => SAFE_SEGMENT.test(s))) return null;
  return `${base.replace(/\/+$/, "")}/api/${segments.join("/")}${search}`;
}

export function upstreamHeaders(incoming: Headers, token: string, proxySecret: string): Headers {
  const out = new Headers({
    authorization: `Bearer ${token}`,
    "x-aegis-proxy-secret": proxySecret,
    accept: "application/json",
  });
  const contentType = incoming.get("content-type");
  if (contentType) out.set("content-type", contentType);
  // On Vercel the platform sets x-forwarded-for to the real client IP (PRD §3.2).
  const forwarded = incoming.get("x-forwarded-for");
  if (forwarded) out.set("x-forwarded-for", forwarded);
  const userAgent = incoming.get("user-agent");
  if (userAgent) out.set("x-aegis-client-ua", userAgent);
  const fingerprint = incoming.get("x-aegis-fingerprint");
  if (fingerprint) out.set("x-aegis-fingerprint", fingerprint);
  return out;
}
