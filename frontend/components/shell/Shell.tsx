import Link from "next/link";

import { tabsFor } from "@/components/shell/tabs";
import type { Me } from "@/lib/server-api";

interface Props {
  me: Me | null;
  signInPath: string;
  signOutPath: string;
}

// Role-aware tab nav (PRD §4.2). Shared and frozen after Gate 0 (M1 §0.2 rule 3).
export function Shell({ me, signInPath, signOutPath }: Props) {
  const tabs = me ? tabsFor(me.roles) : [];
  return (
    <header className="shell">
      <Link href="/" className="logo">
        <i aria-hidden="true" />
        Injection Arena
      </Link>
      <nav aria-label="Main">
        {tabs.map((tab) => (
          <Link key={tab.href} href={tab.href}>
            {tab.label}
          </Link>
        ))}
      </nav>
      <div className="who">
        {me ? (
          <>
            <span className="muted">{me.name ?? me.email ?? "signed in"}</span>
            {/* Auth routes need a full navigation, not a client-side Link. */}
            <a href={signOutPath}>Sign out</a>
          </>
        ) : (
          <a href={signInPath}>Sign in</a>
        )}
      </div>
    </header>
  );
}
