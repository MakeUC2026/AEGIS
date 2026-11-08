import { NextResponse } from "next/server";

import { devAuthAllowed } from "@/lib/dev-auth";
import { DEV_SESSION_COOKIE } from "@/lib/session";

export async function GET() {
  if (!devAuthAllowed()) return new NextResponse(null, { status: 404 });
  const response = new NextResponse(null, { status: 303, headers: { location: "/" } });
  response.cookies.delete(DEV_SESSION_COOKIE);
  return response;
}
