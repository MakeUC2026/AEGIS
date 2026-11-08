import "server-only";

import { redirect } from "next/navigation";

import { ApiError, serverGet } from "@/lib/server-api";

export type Loaded<T> = { ok: true; data: T } | { ok: false; reason: "forbidden" | "notfound" | "unavailable" };

// One place that turns API failures into screen states. A 401 means the session ended.
export async function load<T>(segments: readonly string[], search = ""): Promise<Loaded<T>> {
  try {
    return { ok: true, data: await serverGet<T>(segments, search) };
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 401) redirect("/");
      if (err.status === 403) return { ok: false, reason: "forbidden" };
      if (err.status === 404 || err.status === 422) return { ok: false, reason: "notfound" };
    }
    return { ok: false, reason: "unavailable" };
  }
}
