"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ApiError, apiFetch } from "@/lib/api";

export interface LevelCard {
  level_id: string;
  number: number;
  name: string;
  mode: "off" | "basic" | "strict";
  secret_tier: string;
  divert_enabled: boolean;
  obtained: boolean;
  compromised: boolean;
}

// Level cards (PRD §6.1): all levels open and replayable.
export function LevelPicker({ levels }: { levels: LevelCard[] }) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function start(levelId: string) {
    setBusy(levelId);
    setError(null);
    try {
      const session = await apiFetch<{ id: string }>("arena/sessions", { method: "POST", json: { level_id: levelId } });
      router.push(`/arena/${session.id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : "Could not start the session.");
      setBusy(null);
    }
  }

  return (
    <>
      <div className="level-grid">
        {levels.map((lv) => (
          <section key={lv.level_id} className="level-card" aria-label={lv.name}>
            <header>
              <span className="mode-chip" data-mode={lv.mode}>{lv.mode}</span>
              {lv.compromised ? <span className="tag-warn">compromised</span> : null}
            </header>
            <h2>{lv.name}</h2>
            <p className="muted">Secret: {lv.secret_tier}</p>
            <p className={lv.obtained ? "badge-won" : "muted"}>{lv.obtained ? "Obtained" : "Not yet"}</p>
            <button className="btn-primary" type="button" disabled={busy !== null} onClick={() => start(lv.level_id)}>
              {busy === lv.level_id ? "Starting…" : "Start"}
            </button>
          </section>
        ))}
      </div>
      {error ? <p role="alert" className="error-line">{error}</p> : null}
    </>
  );
}
