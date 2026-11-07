import "server-only";

// Server-side configuration. Values never reach client bundles (CONST-SEC-002/003).

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

export function apiUrl(): string {
  return required("AEGIS_API_URL");
}

export function proxySecret(): string {
  return required("AEGIS_PROXY_SECRET");
}

export function devPrivateKey(): string {
  return required("AEGIS_DEV_JWT_PRIVATE_KEY").replace(/\\n/g, "\n");
}
