"use client";

import { useState } from "react";

import type { AuditRow, EventRow, ForensicRow } from "../_ui/types";
import { Chip, Json, PageHead, Segments, State, WAITING_M2, clock, useApi, words } from "../_ui/ui";
import s from "../_ui/console.module.css";

const VIEWS = ["events", "forensics", "audit"] as const;
const DECISIONS = ["all", "deny", "divert", "review", "human_deny", "allow"] as const;

function Events({ initialId }: { initialId?: string }) {
  const [decision, setDecision] = useState<(typeof DECISIONS)[number]>("all");
  const [selected, setSelected] = useState(initialId);
  const query = decision === "all" ? "" : `&decision=${decision}`;
  const api = useApi<EventRow[]>(`admin/events?limit=300${query}`, 5_000);
  return (
    <>
      <div className={s.toolbar}>
        <Segments label="Filter by decision" value={decision} options={DECISIONS} onChange={setDecision} />
        <small className="muted">{api.updated ? `Updated ${api.updated.toLocaleTimeString()}` : ""}</small>
      </div>
      <State api={api} empty={decision === "all" ? WAITING_M2 : "No events with this decision."}>
        {(rows) => {
          const sel = rows.find((r) => r.event_id === selected) ?? rows[0];
          return (
            <div className={s.logs}>
              <section className="panel" style={{ padding: 0 }} aria-label="Events">
                <ul className={s.list}>
                  {rows.map((e) => (
                    <li key={e.event_id}>
                      <button type="button" className={s.item} aria-pressed={sel.event_id === e.event_id} onClick={() => setSelected(e.event_id)}>
                        <time dateTime={e.time}>{e.time.slice(11, 16)}</time>
                        <Chip value={e.decision} />
                        <span className={s.what}>
                          <b>
                            {words(e.stage)} · score {e.sentinel_score}
                          </b>
                          <small>
                            {e.mode} · {e.rule_ids.join(", ") || "no rule"}
                          </small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
              <aside className={`panel ${s.detail}`} aria-label="Event details">
                <div className={s.panelHead} style={{ marginBottom: 0 }}>
                  <h2>{words(sel.stage)}</h2>
                  <Chip value={sel.decision} />
                </div>
                <div>
                  <dl className={s.kv}>
                    <dt>Sentinel</dt>
                    <dd>{sel.sentinel_score} / 100</dd>
                  </dl>
                  <div className={s.bar} style={{ marginTop: 6 }}>
                    <i style={{ width: `${sel.sentinel_score}%` }} />
                  </div>
                </div>
                <dl className={s.kv}>
                  <dt>Time</dt>
                  <dd>{clock(sel.time)}</dd>
                  <dt>Mode</dt>
                  <dd>
                    <span className="mode-chip" data-mode={sel.mode}>
                      {sel.mode}
                    </span>
                  </dd>
                  <dt>Shadow</dt>
                  <dd>{sel.shadow_decision ? words(sel.shadow_decision) : "–"}</dd>
                  <dt>Rules</dt>
                  <dd className="mono">{sel.rule_ids.join(", ") || "none"}</dd>
                  <dt>Judge</dt>
                  <dd>{sel.judge_risk === null ? "Not run" : `risk ${sel.judge_risk}`}</dd>
                  {sel.judge_reason ? (
                    <>
                      <dt>Reason</dt>
                      <dd>{sel.judge_reason}</dd>
                    </>
                  ) : null}
                  <dt>Forensics</dt>
                  <dd>{sel.forensic_status ?? "–"}</dd>
                  <dt>Session</dt>
                  <dd className="mono">{sel.fw_session_id}</dd>
                  <dt>User</dt>
                  <dd className="mono">{sel.user_id}</dd>
                  <dt>Event</dt>
                  <dd className="mono">{sel.event_id}</dd>
                </dl>
              </aside>
            </div>
          );
        }}
      </State>
    </>
  );
}

function Forensics() {
  const api = useApi<ForensicRow[]>("admin/forensics?limit=100");
  return (
    <State api={api} empty="No forensic reports yet. The worker writes one per blocked event.">
      {(rows) => (
        <div className="fold-list">
          {rows.map((f) => (
            <details key={f.event_id} className="fold" style={{ "--tone": "var(--teal)" } as React.CSSProperties}>
              <summary>
                <h3>{f.attack_family ? words(f.attack_family) : "Unclassified"}</h3>
                <Chip value={f.decision} />
                <Chip value={f.status} />
              </summary>
              <div className="fold-body">
                {f.summary ? <p>{f.summary}</p> : null}
                {f.failure_reason ? <p className={s.err}>{f.failure_reason}</p> : null}
                <dl className={s.kv}>
                  <dt>Stage</dt>
                  <dd>{words(f.stage)}</dd>
                  <dt>Mode</dt>
                  <dd>{f.mode}</dd>
                  <dt>ATLAS</dt>
                  <dd className="mono">{f.atlas_techniques?.join(", ") || "–"}</dd>
                  <dt>Missed</dt>
                  <dd>{f.missed_signals ? JSON.stringify(f.missed_signals) : "–"}</dd>
                  <dt>Would block in</dt>
                  <dd>{f.would_have_blocked_in ? JSON.stringify(f.would_have_blocked_in) : "–"}</dd>
                  <dt>When</dt>
                  <dd>{clock(f.created_at)}</dd>
                </dl>
              </div>
            </details>
          ))}
        </div>
      )}
    </State>
  );
}

function Audit() {
  const api = useApi<AuditRow[]>("admin/audit?limit=100");
  return (
    <State api={api} empty="No changes recorded yet.">
      {(rows) => (
        <div className="fold-list">
          {rows.map((a) => (
            <details key={a.id} className="fold">
              <summary>
                <h3>
                  {words(a.action)} {a.entity}
                </h3>
                <span className="chip mono">{a.entity_id}</span>
                <small className="muted">{clock(a.time)}</small>
              </summary>
              <div className="fold-body">
                <p className="muted mono">by {a.actor_id ?? "system"}</p>
                <div className={s.cards}>
                  <div>
                    <p className="muted">Before</p>
                    <Json value={a.before} />
                  </div>
                  <div>
                    <p className="muted">After</p>
                    <Json value={a.after} />
                  </div>
                </div>
              </div>
            </details>
          ))}
        </div>
      )}
    </State>
  );
}

export function LogsView({ initialId }: { initialId?: string }) {
  const [view, setView] = useState<(typeof VIEWS)[number]>("events");
  return (
    <main className="wide">
      <PageHead title="Live firewall" line="Every decision, its forensics and every config change." />
      <Segments label="View" value={view} options={VIEWS} onChange={setView} />
      {view === "events" ? <Events initialId={initialId} /> : view === "forensics" ? <Forensics /> : <Audit />}
    </main>
  );
}
