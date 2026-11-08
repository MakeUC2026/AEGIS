"use client";

import { useState } from "react";

import { apiFetch } from "@/lib/api";

import type { Draft } from "../_ui/types";
import { Chip, ConsoleTabs, PageHead, Segments, State, act, clock, useApi, words } from "../_ui/ui";
import s from "../_ui/console.module.css";

const STATUSES = ["pending", "failed_validation", "approved", "rejected"] as const;

function Detail({ d, onDone }: { d: Draft; onDone: () => void }) {
  const [body, setBody] = useState(JSON.stringify(d.body, null, 2));
  const [msg, setMsg] = useState<string | null>(null);
  const open = d.status === "pending" || d.status === "failed_validation";
  async function save() {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      setMsg("The body is not valid JSON.");
      return;
    }
    setMsg(await act(() => apiFetch(`admin/drafts/${d.draft_id}`, { method: "PATCH", json: { body: parsed } }), onDone));
  }
  const post = async (verb: "approve" | "reject") => setMsg(await act(() => apiFetch(`admin/drafts/${d.draft_id}/${verb}`, { method: "POST" }), onDone));
  return (
    <aside className={`panel ${s.detail}`} aria-label="Draft">
      <div className={s.panelHead} style={{ marginBottom: 0 }}>
        <h2>{words(d.kind)}</h2>
        <Chip value={d.status} />
      </div>
      <dl className={s.kv}>
        <dt>Cluster</dt>
        <dd>{d.cluster_size} similar</dd>
        <dt>Source event</dt>
        <dd className="mono">{d.source_event_id ?? "–"}</dd>
        <dt>Created</dt>
        <dd>{clock(d.created_at)}</dd>
        {d.result_ref ? (
          <>
            <dt>Result</dt>
            <dd className="mono">{d.result_ref}</dd>
          </>
        ) : null}
      </dl>
      {d.validation?.reasons?.length ? <p className={s.err}>{d.validation.reasons.join(" · ")}</p> : null}
      {d.needs_reconcile ? <p className={s.err}>Approved but not linked to a rule yet. Approve again to reconcile.</p> : null}
      <label className={s.form} style={{ display: "grid" }}>
        <span className="muted">Body</span>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} readOnly={!open} />
      </label>
      {open || d.needs_reconcile ? (
        <div className={s.actions}>
          <button className="btn-primary" type="button" onClick={() => post("approve")}>
            Approve
          </button>
          {open ? (
            <>
              <button className="btn-alt" type="button" onClick={save}>
                Save &amp; revalidate
              </button>
              <button className="btn-alt" type="button" onClick={() => post("reject")}>
                Reject
              </button>
            </>
          ) : null}
        </div>
      ) : null}
      {msg ? (
        <p className={s.err} role="alert">
          {msg}
        </p>
      ) : null}
    </aside>
  );
}

// Drafts (PRD §10.3): forensic suggestions for new rules or patterns, validated before approval.
export default function Drafts() {
  const [status, setStatus] = useState<(typeof STATUSES)[number]>("pending");
  const api = useApi<Draft[]>(`admin/drafts?status=${status}`);
  const [selected, setSelected] = useState<string>();
  return (
    <main className="wide">
      <PageHead title="Firewall console" line="Improvements suggested by the forensic worker." />
      <ConsoleTabs />
      <Segments label="Draft status" value={status} options={STATUSES} onChange={setStatus} />
      <State api={api} empty="No drafts in this status.">
        {(rows) => {
          const d = rows.find((r) => r.draft_id === selected) ?? rows[0];
          return (
            <div className={s.logs}>
              <section className="panel" style={{ padding: 0 }} aria-label="Drafts">
                <ul className={s.list}>
                  {rows.map((r) => (
                    <li key={r.draft_id}>
                      <button type="button" className={s.item} aria-pressed={d.draft_id === r.draft_id} onClick={() => setSelected(r.draft_id)}>
                        <time dateTime={r.created_at}>{r.created_at.slice(5, 10)}</time>
                        <Chip value={r.status} />
                        <span className={s.what}>
                          <b>{words(r.kind)}</b>
                          <small>{r.cluster_size} similar</small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
              <Detail key={d.draft_id} d={d} onDone={api.reload} />
            </div>
          );
        }}
      </State>
    </main>
  );
}
