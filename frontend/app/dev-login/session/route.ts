import { type NextRequest, NextResponse } from "next/server";

import { devAuthAllowed, findDevUser } from "@/lib/dev-auth";
import { DEV_TOKEN_TTL_S, signDevToken } from "@/lib/dev-token";
import { DEV_SESSION_COOKIE } from "@/lib/session";

// Dev sign-in (DD-12). 404 unless AEGIS_AUTH_MODE=dev and APP_ENV is not production.
export async function POST(request: NextRequest) {
  if (!devAuthAllowed()) return new NextResponse(null, { status: 404 });
  const form = await request.formData();
  const user = findDevUser(String(form.get("user") ?? ""));
  if (!user) return NextResponse.json({ detail: "unknown dev user" }, { status: 400 });

  // Relative Location: stays on the origin the browser used (CSP form-action 'self' checks
  // redirect targets too; request.url can report a different host such as localhost).
  const response = new NextResponse(null, { status: 303, headers: { location: "/" } });
  response.cookies.set(DEV_SESSION_COOKIE, await signDevToken(user), {
    httpOnly: true,
    sameSite: "lax",
    secure: request.nextUrl.protocol === "https:",
    path: "/",
    maxAge: DEV_TOKEN_TTL_S,
  });
  return response;
}
