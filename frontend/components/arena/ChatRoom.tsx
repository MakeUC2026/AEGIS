"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { ApiError, apiFetch } from "@/lib/api";
import {
  browserFingerprintParts,
  computeFingerprint,
  inputLocked,
  newMessageId,
  type SessionDetail,
  statusLine,
  type Turn,
  type TurnResponse,
} from "@/lib/arena";

const POLL_INTERVAL_MS = 3000;

interface Recap {
  items: { message_id: string; stage: string; decision: string; rule_ids: string[]; score_band: string }[];
  diverts: { stage: string; tool: string | null; attempted: string; decoy_shown: string }[];
}

function upsert(turns: Turn[], next: Turn): Turn[] {
  const i = turns.findIndex((t) => t.message_id === next.message_id);
  return i === -1 ? [...turns, next] : turns.map((t, j) => (j === i ? next : t));
}

// Chat screen (PRD §6.2): thread, tool-output view, defense feed, win banner, review lock, recap.
export function ChatRoom({ sessionId }: { sessionId: string }) {
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  const [won, setWon] = useState(false);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [recap, setRecap] = useState<Recap | null>(null);
  const [fingerprint, setFingerprint] = useState<string | undefined>(undefined);

  const fetchSession = useCallback(async () => {
    const d = await apiFetch<SessionDetail>(`arena/sessions/${sessionId}`);
    const r = d.status === "closed" ? await apiFetch<Recap>(`arena/sessions/${sessionId}/recap`) : null;
    return { d, r };
  }, [sessionId]);

  const apply = useCallback(({ d, r }: { d: SessionDetail; r: Recap | null }) => {
    setDetail(d);
    setWon(d.won);
    setRecap(r);
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchSession()
      .then((res) => {
        if (!cancelled) apply(res);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof ApiError ? e.detail : "Could not load the session.");
      });
    return () => {
      cancelled = true;
    };
  }, [fetchSession, apply]);

  // Fingerprint only on divert-enabled levels (PRD §8.5, M1-X25).
  useEffect(() => {
    if (detail?.divert_enabled && fingerprint === undefined) {
      void computeFingerprint(browserFingerprintParts()).then(setFingerprint);
    }
  }, [detail?.divert_enabled, fingerprint]);

  const pending = detail?.turns.find((t) => t.status === "awaiting_review" && t.ticket_id);
  useEffect(() => {
    if (!pending?.ticket_id) return;
    const timer = setInterval(async () => {
      try {
        const t = await apiFetch<TurnResponse>(`arena/sessions/${sessionId}/tickets/${pending.ticket_id}`);
        if (t.status !== "awaiting_review") {
          setDetail((d) => (d ? { ...d, turns: upsert(d.turns, t) } : d));
          setWon(t.won);
        }
      } catch {
        /* keep polling; the next tick retries */
      }
    }, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [pending?.ticket_id, sessionId]);

  async function send(text: string, messageId: string) {
    if (!detail) return;
    setError(null);
    const optimistic: Turn = { message_id: messageId, text, status: "sent", reply: null, tool_effects: [], ticket_id: null, defense_feed: [] };
    setDetail({ ...detail, turns: upsert(detail.turns, optimistic) });
    try {
      const t = await apiFetch<TurnResponse>(`arena/sessions/${sessionId}/messages`, {
        method: "POST",
        json: { message_id: messageId, text },
        fingerprint: detail.divert_enabled ? fingerprint : undefined,
      });
      setDetail((d) => (d ? { ...d, turns: upsert(d.turns, t), remaining_messages: t.remaining_messages ?? d.remaining_messages } : d));
      setWon(t.won);
    } catch (e) {
      setDetail((d) => (d ? { ...d, turns: d.turns.filter((x) => x.message_id !== messageId || x.status !== "sent") } : d));
      setError(e instanceof ApiError ? e.detail : "Message failed.");
    }
  }

  async function close() {
    try {
      await apiFetch(`arena/sessions/${sessionId}/close`, { method: "POST" });
      apply(await fetchSession());
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : "Could not close the session.");
    }
  }

  if (!detail) return <p className="muted">{error ?? "Loading session…"}</p>;
  const locked = inputLocked(detail.turns) || detail.status === "closed";
  const effects = detail.turns.flatMap((t) => t.tool_effects);
  const feed = detail.turns.flatMap((t) => t.defense_feed.map((f, i) => ({ ...f, key: `${t.message_id}-${i}` })));

  return (
    <div className="chat-layout">
      <section className="chat-main" aria-label="Conversation">
        <header className="chat-head">
          <div>
            <h1>{detail.level_name}</h1>
            <p className="muted">
              Mode <span className="mode-chip" data-mode={detail.mode}>{detail.mode}</span> · {detail.remaining_messages} messages left this hour
            </p>
          </div>
          <div className="chat-actions">
            <Link className="btn-alt" href="/arena">New session</Link>
            {detail.status === "active" ? (
              <button className="btn-alt" type="button" onClick={close}>Close session</button>
            ) : null}
          </div>
        </header>
        {won ? <p className="win-banner" role="status">Secret obtained. You won this level. You can keep chatting.</p> : null}
        <ol className="thread">
          {detail.turns.map((t) => (
            <li key={t.message_id}>
              <p className="bubble you">{t.text}</p>
              <p className="bubble bot" data-status={t.status}>
                {statusLine(t)}
                {t.status === "not_sent" && detail.status === "active" ? (
                  <button className="link-btn" type="button" onClick={() => send(t.text, t.message_id)}>Retry</button>
                ) : null}
              </p>
            </li>
          ))}
        </ol>
        {error ? <p role="alert" className="error-line">{error}</p> : null}
        <form
          className="composer"
          onSubmit={(e) => {
            e.preventDefault();
            if (draft.trim() && !locked) {
              void send(draft, newMessageId());
              setDraft("");
            }
          }}
        >
          <textarea
            aria-label="Message"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            disabled={locked}
            placeholder={detail.status === "closed" ? "Session closed" : locked ? "Waiting for a reviewer…" : "Talk to the assistant"}
          />
          <button className="btn-primary" type="submit" disabled={locked || !draft.trim()}>Send</button>
        </form>
      </section>
      <aside className="chat-side">
        <section aria-label="Tool output">
          <h2>Tool output</h2>
          {effects.length === 0 ? <p className="muted">No tool effects yet.</p> : null}
          {effects.map((e) => (
            <div key={e.call_id} className="effect" data-state={e.state}>
              <p className="effect-head">{e.tool} · {e.state.replaceAll("_", " ")}</p>
              {e.visible_content ? <pre>{e.visible_content}</pre> : null}
            </div>
          ))}
        </section>
        <section aria-label="Defense feed">
          <h2>Defense feed</h2>
          {feed.length === 0 ? <p className="muted">No checks yet.</p> : null}
          <ul className="feed">
            {feed.map((f) => (
              <li key={f.key} data-decision={f.decision}>
                {f.stage.replaceAll("_", " ")} · <strong>{f.decision}</strong>
                {f.shadow_decision ? <> (would have {f.shadow_decision === "deny" ? "denied" : f.shadow_decision})</> : null}
                {f.rule_ids.length ? <> · {f.rule_ids.join(", ")}</> : null} · {f.score_band}
              </li>
            ))}
          </ul>
        </section>
        {recap ? (
          <section aria-label="Defense recap">
            <h2>Defense recap</h2>
            <ul className="feed">
              {recap.items.map((r, i) => (
                <li key={`${r.message_id}-${i}`} data-decision={r.decision}>
                  {r.stage.replaceAll("_", " ")} · <strong>{r.decision}</strong>
                  {r.rule_ids.length ? <> · {r.rule_ids.join(", ")}</> : null}
                </li>
              ))}
            </ul>
            {recap.diverts.map((d, i) => (
              <div key={i} className="effect" data-state="diverted">
                <p className="effect-head">Diverted: {d.tool ?? d.stage}. What you received was a decoy:</p>
                <pre>{d.decoy_shown}</pre>
              </div>
            ))}
          </section>
        ) : null}
      </aside>
    </div>
  );
}
