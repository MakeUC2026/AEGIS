import "server-only";

import { cookies } from "next/headers";

import { getAuth0 } from "@/lib/auth0";
import { devAuthAllowed } from "@/lib/dev-auth";

// The browser only ever holds an httpOnly session cookie (PRD §4.3 step 5, CONST-SEC-004).
export const DEV_SESSION_COOKIE = "aegis_dev_session";

export async function getAccessToken(): Promise<string | null> {
  if (devAuthAllowed()) {
    return (await cookies()).get(DEV_SESSION_COOKIE)?.value ?? null;
  }
  try {
    const { token } = await getAuth0().getAccessToken();
    return token;
  } catch {
    return null; // not signed in, or the refresh failed
  }
}

export function signInPath(): string {
  return devAuthAllowed() ? "/dev-login" : "/auth/login";
}

export function signUpPath(): string {
  return devAuthAllowed() ? "/dev-login" : "/auth/login?screen_hint=signup";
}

// Google is an Auth0 connection; not offered in dev sign-in mode.
export function googleSignInPath(): string | null {
  return devAuthAllowed() ? null : "/auth/login?connection=google-oauth2";
}

export function signOutPath(): string {
  return devAuthAllowed() ? "/dev-logout" : "/auth/logout";
}
