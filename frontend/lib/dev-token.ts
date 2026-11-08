import "server-only";

import { importPKCS8, SignJWT } from "jose";

import type { DevUser } from "@/lib/dev-auth";
import { devPrivateKey } from "@/lib/server-env";

// Mirrors backend app/auth/testing.py: issuer aegis-dev, audience aegis-dev-api, RS256.
export const DEV_ISSUER = "aegis-dev";
export const DEV_AUDIENCE = "aegis-dev-api";
export const DEV_TOKEN_TTL_S = 8 * 60 * 60;

export async function signDevToken(user: DevUser): Promise<string> {
  const key = await importPKCS8(devPrivateKey(), "RS256");
  return new SignJWT({
    "https://aegis/roles": [...user.roles],
    "https://aegis/name": user.name,
    "https://aegis/email": user.email,
  })
    .setProtectedHeader({ alg: "RS256", kid: "dev" })
    .setSubject(user.id)
    .setIssuer(DEV_ISSUER)
    .setAudience(DEV_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${DEV_TOKEN_TTL_S}s`)
    .sign(key);
}
