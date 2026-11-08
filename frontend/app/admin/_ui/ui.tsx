"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { ApiError, apiFetch } from "@/lib/api";

import type { Decision } from "./types";
import s from "./console.module.css";

// --- data -------------------------------------------------------------------------------------

export interface Api<T> {
  data: T | null;
  error: string | null;
  reload: () => void;
  updated: Date | null;
}

// GET an /api/admin path; re-fetch on `reload` and every `pollMs` when given.
export function useApi<T>(path: string, pollMs?: number): Api<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updated, setUpdated] = useState<Date | null>(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    let live = true;
    apiFetch<T>(path)
      .then((d) => {
        if (!live) return;
        setData(d);
        setError(null);
        setUpdated(new Date());
      })
      .catch((e: unknown) => live && setError(errorText(e)));
    return () => {
      live = false;
    };
  }, [path, tick]);
  useEffect(() => {
    if (!pollMs) return;
    const timer = setInterval(reload, pollMs);
    return () => clearInterval(timer);
  }, [pollMs, reload]);
  return { data, error, reload, updated };
}

// A 422 from the console carries {"reasons": [...]}; show those, else the plain detail.
export function errorText(e: unknown): string {
  if (!(e instanceof ApiError)) return "Something went wrong. Try again.";
  try {
    const parsed: unknown = JSON.parse(e.detail);
    if (parsed && typeof parsed === "object" && "reasons" in parsed) return (parsed as { reasons: string[] }).reasons.join(" · ");
  } catch {
    /* not JSON: plain detail */
  }
  return e.detail;
}

// Run a write, then reload. Returns the error text (or null) for inline display.
export async function act(run: () => Promise<unknown>, after: () => void): Promise<string | null> {
  try {
    await run();
    after();
    return null;
  } catch (e) {
    return errorText(e);
  }
}

// --- pieces -----------------------------------------------------------------------------------

const TONE: Record<string, string> = {
  allow: "good",
  approved: "good",
  enabled: "good",
  deny: "bad",
  human_deny: "bad",
  rejected: "bad",
  failed_validation: "bad",
  review: "warn",
  pending: "warn",
  candidate: "warn",
  divert: "info",
};

export function Chip({ value }: { value: string }) {
  return (
    <span className="chip" data-tone={TONE[value]}>
      {value.replaceAll("_", " ")}
    </span>
  );
}

// Shown where data depends on M2's firewall seams (events, tickets, diverts, insight counts).
export const WAITING_M2 = "Waiting for M2: the firewall event pipeline is not merged yet.";

export const words = (v: string) => v.replaceAll("_", " ");
export const clock = (iso: string) => `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
export const BLOCKED: readonly Decision[] = ["deny", "human_deny", "divert"];

export function PageHead({ eyebrow = "Agent Framework", title, line, children }: { eyebrow?: string; title: string; line?: string; children?: React.ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {line ? <p className="muted">{line}</p> : null}
      </div>
      {children ? <div className="chat-actions">{children}</div> : null}
    </div>
  );
}

// Loading / error / empty, in one place so every screen says it the same way.
export function State<T>({ api, empty, children }: { api: Api<T[]>; empty: string; children: (rows: T[]) => React.ReactNode }) {
  if (api.error && !api.data)
    return (
      <div className={`panel ${s.state}`} role="alert">
        <p>{api.error}</p>
        <button className="btn-alt" type="button" onClick={api.reload}>
          Retry
        </button>
      </div>
    );
  if (!api.data) return <p className={`muted ${s.state}`}>Loading…</p>;
  if (api.data.length === 0) return <p className={`panel muted ${s.state}`}>{empty}</p>;
  return <>{children(api.data)}</>;
}

const CONSOLE = [
  { href: "/admin/review", label: "Review queue" },
  { href: "/admin/rules", label: "Rules" },
  { href: "/admin/levels", label: "Levels" },
  { href: "/admin/drafts", label: "Drafts" },
  { href: "/admin/patterns", label: "Risky patterns" },
  { href: "/admin/diverts", label: "Diverts" },
] as const;

export function ConsoleTabs() {
  const path = usePathname();
  return (
    <nav className={s.tabs} aria-label="Console">
      {CONSOLE.map((t) => (
        <Link key={t.href} href={t.href} aria-current={path === t.href ? "page" : undefined}>
          {t.label}
        </Link>
      ))}
    </nav>
  );
}

export function Segments<T extends string>({ value, options, onChange, label }: { value: T; options: readonly T[]; onChange: (v: T) => void; label: string }) {
  return (
    <div className={s.filters} role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o} type="button" aria-pressed={value === o} onClick={() => onChange(o)}>
          {words(o)}
        </button>
      ))}
    </div>
  );
}

export function Json({ value }: { value: unknown }) {
  return <pre className={s.json}>{JSON.stringify(value, null, 2)}</pre>;
}
