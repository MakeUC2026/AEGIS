"use client";

import { useState } from "react";

import type { DivertAdminItem } from "../_ui/types";
import { ConsoleTabs, PageHead, State, clock, useApi, words } from "../_ui/ui";
import s from "../_ui/console.module.css";

// Diverts and trace-back (PRD §8.4, §8.5): what was attempted, the decoy, and the network trace.
export default function Diverts() {
  const api = useApi<DivertAdminItem[]>("admin/diverts?limit=200", 10_000);
  const [selected, setSelected] = useState<string>();
  return (
    <main className="wide">
      <PageHead title="Firewall console" line="Attacks sent to a decoy, with their trace-back." />
      <ConsoleTabs />
      <State api={api} empty="No diverts yet. A diverted attack shows here with its decoy and trace-back.">
        {(rows) => {
          const d = rows.find((r) => r.divert.event_id === selected) ?? rows[0];
          const tb = d.trace_back;
          return (
            <div className={s.logs}>
              <section className="panel" style={{ padding: 0 }} aria-label="Diverts">
                <ul className={s.list}>
                  {rows.map((r) => (
                    <li key={r.divert.event_id}>
                      <button type="button" className={s.item} aria-pressed={d.divert.event_id === r.divert.event_id} onClick={() => setSelected(r.divert.event_id)}>
                        <time dateTime={r.divert.time}>{r.divert.time.slice(11, 16)}</time>
                        <span className="chip" data-tone="info">
                          {r.divert.tool ?? words(r.divert.stage)}
                        </span>
                        <span className={s.what}>
                          <b>{r.divert.attempted_summary}</b>
                          <small>{clock(r.divert.time)}</small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
              <aside className={`panel ${s.detail}`} aria-label="Divert details">
                <h2>{d.divert.tool ?? words(d.divert.stage)}</h2>
                <div>
                  <p className="muted">Attempted</p>
                  <p className={s.attempt} style={{ margin: 0 }}>
                    &gt; {d.divert.attempted_summary}
                  </p>
                </div>
                <div>
                  <p className="muted">Decoy shown</p>
                  <pre className={s.json}>{d.divert.decoy_shown}</pre>
                </div>
                <h3 style={{ margin: 0, fontSize: "1rem" }}>Trace-back</h3>
                {tb ? (
                  <dl className={s.kv}>
                    <dt>Country</dt>
                    <dd>{tb.country ?? "–"}</dd>
                    <dt>ASN</dt>
                    <dd>{tb.asn ? `${tb.asn} ${tb.asn_org ?? ""}` : "–"}</dd>
                    <dt>Subnet</dt>
                    <dd className="mono">{tb.subnet ?? "–"}</dd>
                    <dt>IP hash</dt>
                    <dd className="mono">{tb.ip_hash ?? "–"}</dd>
                    <dt>Agent</dt>
                    <dd>{tb.user_agent ?? "–"}</dd>
                    <dt>Fingerprint</dt>
                    <dd className="mono">{tb.client_fingerprint ?? "–"}</dd>
                    <dt>Methods</dt>
                    <dd>{tb.methods_used.join(", ") || "–"}</dd>
                    <dt>Tools</dt>
                    <dd>{tb.tools_called.join(", ") || "–"}</dd>
                  </dl>
                ) : (
                  <p className="muted">Trace-back unavailable. It is kept for 30 days.</p>
                )}
                <dl className={s.kv}>
                  <dt>Session</dt>
                  <dd className="mono">{d.fw_session_id}</dd>
                  <dt>User</dt>
                  <dd className="mono">{d.user_id}</dd>
                </dl>
              </aside>
            </div>
          );
        }}
      </State>
    </main>
  );
}
