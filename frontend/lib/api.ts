// Browser-side API helper (PRD §3.3 `lib/api.ts`, shared and frozen after Gate 0).
// Every client component calls FastAPI through the same-origin /api proxy with this helper;
// the browser only sends its session cookie (CONST-SEC-004). Server components use
// lib/server-api.ts instead.

const SAFE_PATH = /^[A-Za-z0-9_-]+(\/[A-Za-z0-9_-]+)*(\?[^#]*)?$/;

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
  }
}

export interface ApiOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  json?: unknown;
  fingerprint?: string; // arena only, on divert-enabled levels (PRD §8.5)
  signal?: AbortSignal;
}

function detailOf(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    return typeof detail === "string" ? detail : JSON.stringify(detail);
  }
  return fallback;
}

/** `path` is relative to /api, e.g. "arena/levels" or "arena/sessions?limit=5". */
export async function apiFetch<T>(path: string, options: ApiOptions = {}): Promise<T> {
  if (!SAFE_PATH.test(path)) throw new ApiError(400, "invalid api path");
  const headers = new Headers({ accept: "application/json" });
  if (options.json !== undefined) headers.set("content-type", "application/json");
  if (options.fingerprint) headers.set("x-aegis-fingerprint", options.fingerprint);

  const res = await fetch(`/api/${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.json === undefined ? undefined : JSON.stringify(options.json),
    credentials: "same-origin",
    cache: "no-store",
    signal: options.signal,
  });
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, detailOf(body, res.statusText || "request failed"));
  return body as T;
}
