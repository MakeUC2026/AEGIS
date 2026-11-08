import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiFetch } from "@/lib/api";

afterEach(() => vi.unstubAllGlobals());

function stubFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockImplementation(
    async () =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("apiFetch (browser helper, shared by every part's UI)", () => {
  it("calls the same-origin /api proxy with JSON and returns the parsed body", async () => {
    const fetchMock = stubFetch(200, { ok: true });
    const out = await apiFetch<{ ok: boolean }>("arena/levels");
    expect(out).toEqual({ ok: true });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/arena/levels");
    expect(init.credentials).toBe("same-origin");
    expect(new Headers(init.headers).get("accept")).toBe("application/json");
  });

  it("sends a JSON body and an optional fingerprint header on POST", async () => {
    const fetchMock = stubFetch(200, {});
    await apiFetch("arena/sessions", { method: "POST", json: { level_id: "lvl-2" }, fingerprint: "f".repeat(64) });
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ level_id: "lvl-2" }));
    const headers = new Headers(init.headers);
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("x-aegis-fingerprint")).toBe("f".repeat(64));
  });

  it("throws ApiError with the status and the server's detail on failure", async () => {
    stubFetch(403, { detail: "forbidden" });
    await expect(apiFetch("admin/rules")).rejects.toMatchObject({ status: 403, detail: "forbidden" });
    await expect(apiFetch("admin/rules")).rejects.toBeInstanceOf(ApiError);
  });

  it("refuses absolute URLs and path traversal so callers cannot leave the /api proxy", async () => {
    stubFetch(200, {});
    await expect(apiFetch("https://evil.example/x")).rejects.toBeInstanceOf(ApiError);
    await expect(apiFetch("../auth/logout")).rejects.toBeInstanceOf(ApiError);
  });
});
