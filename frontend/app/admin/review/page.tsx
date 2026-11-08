"use client";

import { useEffect, useState } from "react";

import { apiFetch } from "@/lib/api";

import type { Ticket } from "../_ui/types";
import { ConsoleTabs, PageHead, State, act, useApi, words } from "../_ui/ui";
import s from "../_ui/console.module.css";

// Review queue (PRD §8.3): held turns, priority alerts first, decide before they expire.
export default function ReviewQueue() {
  const api = useApi<Ticket[]>("admin/tickets", 3_000);
  const [selected, setSelected] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  async function decide(id: string, decision: "ok" | "not_ok") {
    setBusy(true);
    setError(await act(() => apiFetch(`admin/tickets/${id}/decision`, { method: "POST", json: { decision } }), api.reload));
    setBusy(false);
  }

  return (
    <main className="wide">
      <PageHead title="Firewall console" line="Held turns wait here. Nothing runs until you decide." />
      <ConsoleTabs />
      <State api={api} empty="Nothing awaiting review.">
        {(rows) => {
          const sorted = [...rows].sort((a, b) => Number(b.priority_alert) - Number(a.priority_alert) || a.expires_at.localeCompare(b.expires_at));
          const t = sorted.find((x) => x.ticket_id === selected) ?? sorted[0];
          const left = Math.max(0, Math.round((Date.parse(t.expires_at) - now) / 1000));
          return (
            <div className={s.logs}>
              <section className="panel" style={{ padding: 0 }} aria-label="Held turns">
                <ul className={s.list}>
                  {sorted.map((x) => (
                    <li key={x.ticket_id}>
                      <button type="button" className={`${s.item} ${x.priority_alert ? s.priority : ""}`} aria-pressed={t.ticket_id === x.ticket_id} onClick={() => setSelected(x.ticket_id)}>
                        <time dateTime={x.expires_at}>{Math.max(0, Math.round((Date.parse(x.expires_at) - now) / 1000))}s</time>
                        <span className="chip" data-tone={x.priority_alert ? "bad" : "warn"}>
                          {x.priority_alert ? "priority" : words(x.stage)}
                        </span>
                        <span className={s.what}>
                          <b>{x.student_command}</b>
                          <small>score {x.sentinel_score}</small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
              <aside className={`panel ${s.detail}`} aria-label="Ticket">
                <div className={s.panelHead} style={{ marginBottom: 0 }}>
                  <h2>{words(t.stage)}</h2>
                  <span className="chip" data-tone={left < 15 ? "bad" : "warn"}>
                    {left}s left
                  </span>
                </div>
                <p className={s.attempt} style={{ margin: 0 }}>
                  &gt; {t.student_command}
                </p>
                {t.held_tool ? (
                  <div>
                    <p className="muted">Held tool call</p>
                    <pre className={s.json}>
                      {t.held_tool} {JSON.stringify(t.held_args, null, 2)}
                    </pre>
                  </div>
                ) : null}
                {t.held_reply ? (
                  <div>
                    <p className="muted">Held reply</p>
                    <pre className={s.json}>{t.held_reply}</pre>
                  </div>
                ) : null}
                <dl className={s.kv}>
                  <dt>Sentinel</dt>
                  <dd>{t.sentinel_score}</dd>
                  <dt>Breakdown</dt>
                  <dd>
                    {Object.entries(t.score_breakdown)
                      .map(([k, v]) => `${k} ${v ?? "not run"}`)
                      .join(" · ")}
                  </dd>
                  <dt>Rules</dt>
                  <dd className="mono">{t.rule_ids.join(", ") || "none"}</dd>
                  <dt>Session</dt>
                  <dd className="mono">{t.fw_session_id}</dd>
                </dl>
                <div className={s.actions}>
                  <button className="btn-primary" type="button" disabled={busy} onClick={() => decide(t.ticket_id, "ok")}>
                    OK, let it run
                  </button>
                  <button className="btn-alt" type="button" disabled={busy} onClick={() => decide(t.ticket_id, "not_ok")}>
                    Not OK · human deny
                  </button>
                </div>
                {error ? (
                  <p className={s.err} role="alert">
                    {error}
                  </p>
                ) : null}
              </aside>
            </div>
          );
        }}
      </State>
    </main>
  );
}
