"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import s from "./admin.module.css";

// PRD §11 P0 screens. P1 (Forensics, Audit) and P2 (Live metrics) come in Phase D.
const SCREENS = [
  { href: "/admin/review", label: "Review queue" },
  { href: "/admin/rules", label: "Rules" },
  { href: "/admin/levels", label: "Levels" },
  { href: "/admin/drafts", label: "Drafts" },
  { href: "/admin/patterns", label: "Risky patterns" },
  { href: "/admin/diverts", label: "Diverts" },
] as const;

export function AdminNav() {
  const path = usePathname();
  return (
    <nav className={s.nav} aria-label="Firewall console">
      {SCREENS.map(({ href, label }) => (
        <Link key={href} href={href} aria-current={path === href ? "page" : undefined}>
          {label}
        </Link>
      ))}
    </nav>
  );
}
