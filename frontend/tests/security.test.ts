import { describe, expect, it } from "vitest";

import { buildCsp, newNonce } from "@/lib/csp";
import { isSameOriginRequest } from "@/lib/same-origin";

const directive = (csp: string, name: string) =>
  csp.split(";").map((d) => d.trim()).find((d) => d.startsWith(`${name} `)) ?? "";

describe("buildCsp (ZAP 10055: no 'unsafe-inline' scripts)", () => {
  it("allows scripts only by nonce plus strict-dynamic in production", () => {
    const csp = buildCsp("abc123", false);
    const scripts = directive(csp, "script-src");
    expect(scripts).toContain("'nonce-abc123'");
    expect(scripts).toContain("'strict-dynamic'");
    expect(scripts).not.toContain("'unsafe-inline'");
    expect(scripts).not.toContain("'unsafe-eval'");
  });

  it("adds 'unsafe-eval' only in development", () => {
    expect(directive(buildCsp("n", true), "script-src")).toContain("'unsafe-eval'");
  });

  it("keeps the other locked-down directives", () => {
    const csp = buildCsp("n", false);
    expect(directive(csp, "default-src")).toBe("default-src 'self'");
    expect(directive(csp, "frame-ancestors")).toBe("frame-ancestors 'none'");
    expect(directive(csp, "object-src")).toBe("object-src 'none'");
    expect(directive(csp, "base-uri")).toBe("base-uri 'self'");
    expect(directive(csp, "font-src")).toBe("font-src 'self'");
    expect(directive(csp, "form-action")).toBe("form-action 'self' https://*.auth0.com");
  });

  it("nonces are fresh base64 values", () => {
    const a = newNonce();
    expect(a).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(a.length).toBeGreaterThanOrEqual(22);
    expect(newNonce()).not.toBe(a);
  });
});

describe("isSameOriginRequest (ZAP 10202: cross-site form posts)", () => {
  const h = (init: Record<string, string>) => new Headers(init);

  it("accepts a same-origin fetch metadata header", () => {
    expect(isSameOriginRequest(h({ "sec-fetch-site": "same-origin", host: "a.test" }))).toBe(true);
  });

  it("rejects cross-site and same-site fetch metadata even if Origin is spoofed to match", () => {
    expect(isSameOriginRequest(h({ "sec-fetch-site": "cross-site", origin: "http://a.test", host: "a.test" }))).toBe(false);
    expect(isSameOriginRequest(h({ "sec-fetch-site": "same-site", origin: "http://a.test", host: "a.test" }))).toBe(false);
  });

  it("falls back to Origin vs Host when fetch metadata is absent", () => {
    expect(isSameOriginRequest(h({ origin: "http://127.0.0.1:3000", host: "127.0.0.1:3000" }))).toBe(true);
    expect(isSameOriginRequest(h({ origin: "https://evil.example", host: "127.0.0.1:3000" }))).toBe(false);
  });

  it("treats an explicit default port in Host as the same origin", () => {
    expect(isSameOriginRequest(h({ origin: "https://app.example", host: "app.example:443" }))).toBe(true);
    expect(isSameOriginRequest(h({ origin: "http://app.example", host: "app.example:80" }))).toBe(true);
    expect(isSameOriginRequest(h({ origin: "https://app.example", host: "app.example:8443" }))).toBe(false);
  });

  it("prefers x-forwarded-host behind a proxy", () => {
    expect(
      isSameOriginRequest(h({ origin: "https://app.example", host: "internal:3000", "x-forwarded-host": "app.example" })),
    ).toBe(true);
  });

  it("rejects when neither signal is present or Origin is malformed", () => {
    expect(isSameOriginRequest(h({ host: "a.test" }))).toBe(false);
    expect(isSameOriginRequest(h({ origin: "null", host: "a.test" }))).toBe(false);
  });
});
