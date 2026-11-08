import "server-only";

import { redirect } from "next/navigation";

import { getMe } from "@/lib/server-api";

import { viewerKind } from "./access";
import type { ViewerKind } from "./types";

export interface Viewer {
  id: string;
  /** SHELL ONLY: mock rows are keyed by display name (see _lib/mock.ts). */
  ownerKey: string;
  name: string;
  roles: string[];
  kind: ViewerKind;
}

// Signed-out visitors go to the sign-in page. Role checks happen per screen (and again in the API).
export async function requireViewer(): Promise<Viewer> {
  const me = await getMe();
  if (!me) redirect("/");
  const name = me.name ?? me.email ?? "you";
  return { id: me.id, ownerKey: name, name, roles: me.roles, kind: viewerKind(me.roles) };
}
