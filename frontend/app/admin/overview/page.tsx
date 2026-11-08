"use client";

import Link from "next/link";

import type { EventRow, Ticket } from "../_ui/types";
import { BLOCKED, Chip, PageHead, clock, useApi, words } from "../_ui/ui";
import s from "../_ui/console.module.css";

const LIMIT = 200;

// Admin home: counts over the latest events and pending reviews, then the recent events.
export default function Overview() {
  const events = useApi<EventRow[]>(`admin/events?limit=${LIMIT}`, 10_000);
  const tickets = useApi<Ticket[]>("admin/tickets", 10_000);
  const rows = events.data ?? [];
  const cards = [
    { label: `Latest ${LIMIT} events`, value: rows.length, note: "decisions logged" },
    { label: "Blocked", value: rows.filter((e) => BLOCKED.includes(e.decision)).length, note: "denied or diverted" },
    { label: "Awaiting review", value: tickets.data?.length ?? "–", note: "held, not executed", href: "/admin/review" },
    { label: "Diverted", value: rows.filter((e) => e.decision === "divert").length, note: "decoy served" },
  ];
  return (
    <main>
      <PageHead title="Security overview" line="What the firewall decided, live from the event log." />
      <div className={s.kpis}>
        {cards.map((c) => (
          <div key={c.label} className={`panel ${s.kpi}`}>
            <span>{c.label}</span>
            <strong>{events.data || c.href ? c.value : "–"}</strong>
            {c.href ? <Link href={c.href}>{c.note}</Link> : <small>{c.note}</small>}
          </div>
        ))}
      </div>
      <section className="panel" aria-labelledby="h-recent">
        <div className={s.panelHead}>
          <h2 id="h-recent">Recent events</h2>
          <Link href="/admin/logs">View all</Link>
        </div>
        {events.error ? <p className={s.err}>{events.error}</p> : null}
        {events.data && rows.length === 0 ? <p className="muted">No events yet.</p> : null}
        <ul className={s.health}>
          {rows.slice(0, 15).map((e) => (
            <li key={e.event_id}>
              <span>
                <Link href={`/admin/logs?event=${e.event_id}`}>
                  {words(e.stage)} · score {e.sentinel_score}
                </Link>
                <small>
                  {e.mode} · {clock(e.time)}
                </small>
              </span>
              <Chip value={e.decision} />
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
