import { redirect } from "next/navigation";
import type { ReactNode } from "react";

import { getMe } from "@/lib/server-api";

import { AdminNav } from "./AdminNav";
import s from "./admin.module.css";

// Hiding the tab is not the control (I-4): every /api/admin route checks the role on the server.
// This guard only keeps non-admins off pages that would show nothing but 403s.
export default async function AdminLayout({ children }: { children: ReactNode }) {
  const me = await getMe();
  if (!me) redirect("/");
  if (!me.roles.includes("firewall_admin")) redirect("/");
  return (
    <main className={s.wrap}>
      <h1>Firewall console</h1>
      <AdminNav />
      {children}
    </main>
  );
}
