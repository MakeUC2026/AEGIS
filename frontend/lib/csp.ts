// Per-request Content-Security-Policy (ZAP 10055). Scripts run only with the request's nonce;
// 'strict-dynamic' lets those scripts load Next's chunks. Next reads the nonce from the request's
// CSP header and stamps it on its own inline scripts, which needs dynamic rendering (every page
// is, because the root layout reads the session). style-src keeps 'unsafe-inline' because React
// style attributes cannot carry a nonce; style injection alone cannot run script.

export function newNonce(): string {
  return Buffer.from(crypto.randomUUID()).toString("base64");
}

export function buildCsp(nonce: string, isDev: boolean): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self' https://*.auth0.com",
    "object-src 'none'",
  ].join("; ");
}
