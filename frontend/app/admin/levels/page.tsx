"use client";

import { useState } from "react";

import { apiFetch } from "@/lib/api";

import type { LevelSummary } from "../_ui/types";
import { ConsoleTabs, PageHead, State, act, clock, useApi } from "../_ui/ui";
import s from "../_ui/console.module.css";

const THRESHOLDS = ["review", "deny", "divert", "alert"] as const;

function LevelCard({ level, onSaved }: { level: LevelSummary; onSaved: () => void }) {
  const [thresholds, setThresholds] = useState(level.thresholds);
  const [weights, setWeights] = useState(level.weights);
  const [timeout, setTimeoutS] = useState(level.review_timeout_s);
  const [divert, setDivert] = useState(level.divert_enabled);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  async function save() {
    const json = { thresholds, weights, review_timeout_s: timeout, divert_enabled: divert };
    const err = await act(() => apiFetch(`admin/levels/${level.level_id}/versions`, { method: "POST", json }), onSaved);
    setMsg(err ? { ok: false, text: err } : { ok: true, text: "Saved as a new version." });
  }
  return (
    <section className="panel" aria-label={level.name}>
      <div className={s.panelHead}>
        <h2>
          {level.number}. {level.name}
        </h2>
        <span className="chip">
          v{level.level_version} · {clock(level.created_at)}
        </span>
      </div>
      <div className={s.form}>
        <label>
          Review timeout (s)
          <input type="number" value={timeout} onChange={(e) => setTimeoutS(Number(e.target.value))} />
        </label>
        {THRESHOLDS.map((k) => (
          <label key={k}>
            {k} at
            <input type="number" min={0} max={100} value={thresholds[k] ?? 0} onChange={(e) => setThresholds({ ...thresholds, [k]: Number(e.target.value) })} />
          </label>
        ))}
        {Object.keys(weights).map((k) => (
          <label key={k}>
            weight: {k}
            <input type="number" min={5} max={60} value={weights[k]} onChange={(e) => setWeights({ ...weights, [k]: Number(e.target.value) })} />
          </label>
        ))}
        <label className={`full ${s.check}`}>
          <input type="checkbox" checked={divert} onChange={(e) => setDivert(e.target.checked)} />
          Divert to decoys
        </label>
        <div className={`full ${s.actions}`}>
          <button className="btn-primary" type="button" onClick={save}>
            Save new version
          </button>
          {msg ? (
            <p className={msg.ok ? s.ok : s.err} role="status">
              {msg.text}
            </p>
          ) : null}
        </div>
      </div>
    </section>
  );
}

// Levels (PRD §11): every save is a new level version; running sessions keep theirs.
export default function Levels() {
  const api = useApi<LevelSummary[]>("admin/levels");
  return (
    <main className="wide">
      <PageHead title="Firewall console" line="Each save is a new version. Running sessions keep theirs." />
      <ConsoleTabs />
      <State api={api} empty="No levels available.">
        {(rows) => (
          <div className={s.cards}>
            {rows.map((l) => (
              <LevelCard key={`${l.level_id}-${l.level_version}`} level={l} onSaved={api.reload} />
            ))}
          </div>
        )}
      </State>
    </main>
  );
}
