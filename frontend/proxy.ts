import { type NextRequest, NextResponse } from "next/server";

import { getAuth0 } from "@/lib/auth0";
import { buildCsp, newNonce } from "@/lib/csp";
import { devAuthAllowed } from "@/lib/dev-auth";

// Next.js 16 proxy (formerly middleware): sets a per-request nonce CSP (lib/csp.ts), mounts the
// Auth0 /auth/* routes and keeps the session rolling. Dev sign-in mode (DD-12) needs no Auth0.
export async function proxy(request: NextRequest) {
  const csp = buildCsp(newNonce(), process.env.NODE_ENV === "development");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  if (!devAuthAllowed()) {
    const auth = await getAuth0().middleware(request);
    // /auth/* routes and redirects are Auth0's own responses; return them as they are.
    if (request.nextUrl.pathname.startsWith("/auth/") || !auth.headers.has("x-middleware-next")) {
      auth.headers.set("content-security-policy", csp);
      return auth;
    }
    // Otherwise keep Auth0's headers (rolling-session cookies, no-store cache headers) on our
    // pass-through response; ours carries the request-header override with the nonce.
    auth.headers.forEach((value, key) => {
      if (key !== "set-cookie" && !key.startsWith("x-middleware-")) response.headers.set(key, value);
    });
    for (const cookie of auth.headers.getSetCookie()) response.headers.append("set-cookie", cookie);
  }
  response.headers.set("content-security-policy", csp);
  return response;
}

export const config = {
  // Only hashed build assets skip the proxy; every HTML response (404s included) gets the CSP.
  matcher: ["/((?!_next/static|_next/image).*)"],
};
