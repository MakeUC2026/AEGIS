import "server-only";

import { Auth0Client } from "@auth0/nextjs-auth0/server";

// Auth0 Universal Login (PRD §4.3). Reads AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET,
// AUTH0_SECRET and APP_BASE_URL from the environment. Created lazily so dev mode (DD-12)
// never needs Auth0 settings.

let client: Auth0Client | null = null;

export function getAuth0(): Auth0Client {
  client ??= new Auth0Client({
    authorizationParameters: {
      audience: process.env.AUTH0_AUDIENCE,
      scope: "openid profile email",
    },
  });
  return client;
}
