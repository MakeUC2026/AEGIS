"use client";

import { useState } from "react";

import { apiFetch } from "@/lib/api";

import type { Pattern } from "../_ui/types";
import { Chip, ConsoleTabs, Json, PageHead, Segments, State, act, errorText, useApi } from "../_ui/ui";
import s from "../_ui/console.module.css";

const STATUSES = ["candidate", "approved", "rejected", "retired"] as const;

function Detail({ p, onDone }: { p: Pattern; onDone: () => void }) {
  const [conditions, setConditions] = useState(JSON.stringify(p.conditions, null, 2));
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const fail = (text: string | null) => setMsg(text ? { ok: false, text } : null);

  async function save() {
    try {
      const parsed: unknown = JSON.parse(conditions);
      fail(await act(() => apiFetch(`admin/patterns/${p.pattern_id}`, { method: "PATCH", json: { conditions: parsed } }), onDone));
    } catch {
      fail("Conditions are not valid JSON.");
    }
  }
  async function check() {
    try {
      const { reasons } = await apiFetch<{ reasons: string[] }>(`admin/patterns/${p.pattern_id}/check`, { method: "POST" });
      setMsg(reasons.length ? { ok: false, text: reasons.join(" · ") } : { ok: true, text: "All three checks pass. Ready to approve." });
    } catch (e) {
      fail(errorText(e));
    }
  }
  const post = async (verb: "approve" | "reject" | "retire") => fail(await act(() => apiFetch(`admin/patterns/${p.pattern_id}/${verb}`, { method: "POST" }), onDone));

  return (
    <aside className={`panel ${s.detail}`} aria-label="Pattern">
      <div className={s.panelHead} style={{ marginBottom: 0 }}>
        <h2 className="mono">{p.tool}</h2>
        <Chip value={p.status} />
      </div>
      <dl className={s.kv}>
        <dt>Approved in</dt>
        <dd>{p.approved_in_version ?? "–"}</dd>
        <dt>Retired in</dt>
        <dd>{p.retired_in_version ?? "–"}</dd>
        <dt>Source event</dt>
        <dd className="mono">{p.source_event_id ?? "–"}</dd>
      </dl>
      {p.source_args ? (
        <div>
          <p className="muted">Arguments it came from</p>
          <Json value={p.source_args} />
        </div>
      ) : null}
      <label className={s.form} style={{ display: "grid" }}>
        <span className="muted">Conditions</span>
        <textarea value={conditions} onChange={(e) => setConditions(e.target.value)} readOnly={p.status !== "candidate"} />
      </label>
      <div className={s.actions}>
        {p.status === "candidate" ? (
          <>
            <button className="btn-alt" type="button" onClick={check}>
              Check
            </button>
            <button className="btn-primary" type="button" onClick={() => post("approve")}>
              Approve
            </button>
            <button className="btn-alt" type="button" onClick={save}>
              Save
            </button>
            <button className="btn-alt" type="button" onClick={() => post("reject")}>
              Reject
            </button>
          </>
        ) : null}
        {p.status === "approved" ? (
          <button className="btn-alt" type="button" onClick={() => post("retire")}>
            Retire
          </button>
        ) : null}
      </div>
      {msg ? (
        <p className={msg.ok ? s.ok : s.err} role="status">
          {msg.text}
        </p>
      ) : null}
    </aside>
  );
}

// Risky patterns (PRD §7.5): candidates from repeated tool-call attacks; check, then approve.
export default function Patterns() {
  const [status, setStatus] = useState<(typeof STATUSES)[number]>("candidate");
  const api = useApi<Pattern[]>(`admin/patterns?status=${status}`);
  const [selected, setSelected] = useState<string>();
  return (
    <main className="wide">
      <PageHead title="Firewall console" line="Tool-call shapes that keep showing up in attacks." />
      <ConsoleTabs />
      <Segments label="Pattern status" value={status} options={STATUSES} onChange={setStatus} />
      <State api={api} empty="No patterns in this status.">
        {(rows) => {
          const p = rows.find((r) => r.pattern_id === selected) ?? rows[0];
          return (
            <div className={s.logs}>
              <section className="panel" style={{ padding: 0 }} aria-label="Patterns">
                <ul className={s.list}>
                  {rows.map((r) => (
                    <li key={r.pattern_id}>
                      <button type="button" className={s.item} aria-pressed={p.pattern_id === r.pattern_id} onClick={() => setSelected(r.pattern_id)}>
                        <time dateTime={r.created_at}>{r.created_at.slice(5, 10)}</time>
                        <Chip value={r.status} />
                        <span className={s.what}>
                          <b className="mono">{r.tool}</b>
                          <small>{r.conditions.map((c) => `${c.arg} ${c.op}`).join(" · ")}</small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
              <Detail key={p.pattern_id} p={p} onDone={api.reload} />
            </div>
          );
        }}
      </State>
    </main>
  );
}
