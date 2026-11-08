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

const MODE_LINE: Record<LevelCard["mode"], string> = {
  off: "No defense. Learn how injection works.",
  basic: "Rules check every message.",
  strict: "Rules, an AI judge and decoys.",
};

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
          <section key={lv.level_id} className="level-card" data-mode={lv.mode} aria-label={lv.name}>
            <header>
              <span className="level-no">LEVEL {lv.number}</span>
              <span className="mode-chip" data-mode={lv.mode}>{lv.mode}</span>
              {lv.compromised ? <span className="tag-warn">compromised</span> : null}
            </header>
            <h2>{lv.name}</h2>
            <p className="muted">{MODE_LINE[lv.mode]}</p>
            {lv.obtained ? <p className="badge-won">Secret obtained</p> : null}
            <button className="btn-primary" type="button" disabled={busy !== null} onClick={() => start(lv.level_id)}>
              {busy === lv.level_id ? "Starting…" : lv.obtained ? "Play again" : "Start"}
            </button>
          </section>
        ))}
      </div>
      {error ? <p role="alert" className="error-line">{error}</p> : null}
    </>
  );
}
