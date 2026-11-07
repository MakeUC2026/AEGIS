import "server-only";

import { headers } from "next/headers";

import { getAccessToken } from "@/lib/session";
import { apiUrl, proxySecret } from "@/lib/server-env";
import { buildUpstreamUrl, upstreamHeaders } from "@/lib/upstream";

export interface Me {
  id: string;
  name: string | null;
  email: string | null;
  roles: string[];
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

// Server components call FastAPI directly with the same headers the /api route handler sends.
export async function serverGet<T>(segments: readonly string[], search = ""): Promise<T> {
  const token = await getAccessToken();
  if (!token) throw new ApiError(401, "not signed in");
  const url = buildUpstreamUrl(apiUrl(), segments, search);
  if (!url) throw new ApiError(400, "bad path");
  const res = await fetch(url, {
    headers: upstreamHeaders(await headers(), token, proxySecret()),
    cache: "no-store",
  });
  if (!res.ok) throw new ApiError(res.status, `GET ${segments.join("/")} failed`);
  return (await res.json()) as T;
}

export async function getMe(): Promise<Me | null> {
  try {
    return await serverGet<Me>(["me"]);
  } catch {
    return null;
  }
}
