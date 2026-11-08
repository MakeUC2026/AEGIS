import { describe, expect, it } from "vitest";

import { tabsFor } from "@/components/shell/tabs";
import { devAuthAllowed, DEV_USERS } from "@/lib/dev-auth";
import { buildUpstreamUrl, upstreamHeaders } from "@/lib/upstream";

describe("tabsFor (PRD §4.2 tab table)", () => {
  it("student sees arena, own sessions and quizzes only", () => {
    expect(tabsFor(["student"]).map((t) => t.href)).toEqual(["/arena", "/arena/sessions", "/quiz"]);
  });

  it("teacher sees classroom but not the arena", () => {
    const hrefs = tabsFor(["teacher"]).map((t) => t.href);
    expect(hrefs).toContain("/classroom");
    expect(hrefs).not.toContain("/arena");
    expect(hrefs).not.toContain("/admin");
  });

  it("firewall admin sees arena (test sessions), classroom read-only and the firewall console", () => {
    const hrefs = tabsFor(["firewall_admin"]).map((t) => t.href);
    expect(hrefs).toEqual(expect.arrayContaining(["/arena", "/classroom", "/admin"]));
    expect(hrefs).not.toContain("/quiz");
  });

  it("dual-role user gets the union without duplicates", () => {
    const hrefs = tabsFor(["teacher", "firewall_admin"]).map((t) => t.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
    expect(hrefs).toEqual(expect.arrayContaining(["/arena", "/classroom", "/admin"]));
  });

  it("unknown roles give no extra tabs", () => {
    expect(tabsFor(["superuser"])).toEqual([]);
  });
});

describe("buildUpstreamUrl", () => {
  const base = "http://api:8000";

  it("maps /api/<segments> onto the FastAPI /api path and keeps the query", () => {
    expect(buildUpstreamUrl(base, ["arena", "sessions"], "?limit=5")).toBe(
      "http://api:8000/api/arena/sessions?limit=5",
    );
  });

  it.each([[[".."]], [["arena", "..", "admin"]], [["a%2F..%2Fb"]], [["x y"]], [[]]])(
    "rejects unsafe path segments %j",
    (segments) => {
      expect(buildUpstreamUrl(base, segments as string[], "")).toBeNull();
    },
  );
});

describe("upstreamHeaders", () => {
  it("sends the token and proxy secret, forwards client IP, UA and fingerprint, drops cookies", () => {
    const incoming = new Headers({
      cookie: "appSession=abc",
      "x-forwarded-for": "203.0.113.7",
      "user-agent": "Mozilla/5.0",
      "x-aegis-fingerprint": "a".repeat(64),
      "content-type": "application/json",
      "x-aegis-proxy-secret": "spoofed-by-browser",
    });
    const out = upstreamHeaders(incoming, "tok.en.sig", "server-secret");
    expect(out.get("authorization")).toBe("Bearer tok.en.sig");
    expect(out.get("x-aegis-proxy-secret")).toBe("server-secret");
    expect(out.get("x-forwarded-for")).toBe("203.0.113.7");
    expect(out.get("x-aegis-client-ua")).toBe("Mozilla/5.0");
    expect(out.get("x-aegis-fingerprint")).toBe("a".repeat(64));
    expect(out.get("content-type")).toBe("application/json");
    expect(out.get("cookie")).toBeNull();
  });
});

describe("dev auth guard (DD-12)", () => {
  it("is refused in production even if requested", () => {
    expect(devAuthAllowed({ AEGIS_AUTH_MODE: "dev", APP_ENV: "production" })).toBe(false);
  });

  it("is allowed only when explicitly requested outside production", () => {
    expect(devAuthAllowed({ AEGIS_AUTH_MODE: "dev", APP_ENV: "development" })).toBe(true);
    expect(devAuthAllowed({ AEGIS_AUTH_MODE: "auth0", APP_ENV: "development" })).toBe(false);
    expect(devAuthAllowed({})).toBe(false);
  });

  it("offers one seeded user per role combination", () => {
    const roleSets = DEV_USERS.map((u) => [...u.roles].sort().join("+"));
    expect(roleSets).toEqual(
      expect.arrayContaining(["", "teacher", "firewall_admin", "firewall_admin+teacher"]),
    );
  });
});
