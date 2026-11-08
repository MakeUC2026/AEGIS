// Same-origin check for state-changing requests (ZAP 10202). Session cookies are SameSite=Lax,
// which already stops most cross-site POSTs; this is the second layer. Fetch metadata
// (Sec-Fetch-Site) wins when the browser sends it; otherwise Origin must match the host the
// browser used. Requests with neither signal are refused.

export function isSameOriginRequest(headers: Headers): boolean {
  const site = headers.get("sec-fetch-site");
  if (site) return site === "same-origin";

  const origin = headers.get("origin");
  const host = headers.get("x-forwarded-host")?.split(",")[0]?.trim() || headers.get("host");
  if (!origin || !host) return false;
  try {
    const o = new URL(origin);
    // Parse Host with the Origin's scheme so an explicit default port (":443") normalizes away.
    return o.host === new URL(`${o.protocol}//${host}`).host;
  } catch {
    return false;
  }
}
