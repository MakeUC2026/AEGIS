"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { Icon, LogoMark } from "@/components/shell/Icon";
import { activeHref, type Section } from "@/components/shell/tabs";

interface Props {
  sections: Section[];
  name: string;
  roleLabel: string;
  signOutPath: string;
}

// App sidebar: logo, the two sections (Agent Framework / Classroom) and the account.
// Below 900px it collapses to a top bar with a menu button.
export function Shell({ sections, name, roleLabel, signOutPath }: Props) {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  const current = activeHref(
    sections.flatMap((s) => s.tabs),
    path,
  );
  return (
    <aside className="side" data-open={open}>
      <div className="side-top">
        <Link href="/" className="brandmark" aria-label="AEGIS home">
          <LogoMark />
          <span>
            <b>AEGIS</b>
            <small>Agent security</small>
          </span>
        </Link>
        <button className="btn-alt menu-btn" type="button" aria-expanded={open} aria-controls="side-nav" onClick={() => setOpen(!open)}>
          <Icon name="menu" />
          <span>Menu</span>
        </button>
      </div>
      <nav id="side-nav" className="side-nav" aria-label="Main">
        {sections.map((s) => (
          <div key={s.id} data-section={s.id}>
            <p className="side-label" data-section={s.id}>
              {s.label}
            </p>
            <ul>
              {s.tabs.map((t) => (
                <li key={t.href}>
                  <Link href={t.href} aria-current={t.href === current ? "page" : undefined} onClick={() => setOpen(false)}>
                    <Icon name={t.icon} />
                    {t.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <div className="side-user">
        <span className="avatar" aria-hidden="true">
          {name.slice(0, 1).toUpperCase()}
        </span>
        <span className="who">
          <strong>{name}</strong>
          <span>{roleLabel}</span>
        </span>
        {/* Auth routes need a full navigation, not a client-side Link. */}
        <a href={signOutPath}>Sign out</a>
      </div>
    </aside>
  );
}
