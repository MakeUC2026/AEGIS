import { type NextRequest, NextResponse } from "next/server";

import { getAuth0 } from "@/lib/auth0";
import { devAuthAllowed } from "@/lib/dev-auth";

// Next.js 16 proxy (formerly middleware): mounts the Auth0 /auth/* routes and keeps the session
// rolling. Dev sign-in mode (DD-12) needs no Auth0 and passes straight through.
export async function proxy(request: NextRequest) {
  if (devAuthAllowed()) return NextResponse.next();
  return getAuth0().middleware(request);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)"],
};
