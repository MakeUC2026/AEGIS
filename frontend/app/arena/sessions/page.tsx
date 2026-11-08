import Link from "next/link";
import { redirect } from "next/navigation";

import { CloseButton } from "@/components/arena/CloseButton";
import type { ArenaSession } from "@/lib/arena";
import { getMe, serverGet } from "@/lib/server-api";

interface Recap {
  items: { message_id: string; stage: string; decision: string; rule_ids: string[] }[];
  diverts: { stage: string; tool: string | null; attempted: string; decoy_shown: string }[];
}

const TONE: Record<string, string> = { deny: "bad", human_deny: "bad", review: "warn", divert: "info", allow: "good" };
const words = (s: string) => s.replaceAll("_", " ");

// My sessions (PRD §4.2 own sessions only; §6.3 close from the list). Closed sessions show what the
// student tried and what stopped them (GET recap, which only answers once a session is closed).
export default async function MySessionsPage() {
  if (!(await getMe())) redirect("/");
  const sessions = await serverGet<ArenaSession[]>(["arena", "sessions"]);
  const recaps = await Promise.all(
    sessions.map((s) => (s.status === "closed" ? serverGet<Recap>(["arena", "sessions", s.id, "recap"]).catch(() => null) : null)),
  );
  return (
    <main>
      <div className="page-head">
        <div>
          <p className="eyebrow learn">Classroom</p>
          <h1>My sessions</h1>
          <p className="muted">What you tried, and what stopped you.</p>
        </div>
        <Link className="btn-alt" href="/arena">
          New session
        </Link>
      </div>
      {sessions.length === 0 ? (
        <p className="muted">
          No sessions yet. <Link href="/arena">Pick a level</Link> to start.
        </p>
      ) : (
        <div className="card-grid">
          {sessions.map((s, i) => {
            const recap = recaps[i];
            const stops = recap?.items.filter((x) => x.decision !== "allow").length ?? 0;
            return (
              <section key={s.id} className="level-card" data-mode={s.mode} aria-label={s.level_name ?? "Session"}>
                <header>
                  <span className="mode-chip" data-mode={s.mode}>
                    {s.mode}
                  </span>
                  <span className="chip" data-tone={s.status === "active" ? "info" : undefined}>
                    {s.status}
                  </span>
                </header>
                <h2>{s.level_name ?? "Session"}</h2>
                <p className="muted">{new Date(s.started_at).toLocaleString()}</p>
                {s.won ? <p className="badge-won">Secret obtained</p> : <p className="muted">Secret not obtained</p>}
                {s.status === "closed" ? (
                  <details className="fold" style={{ boxShadow: "none" }}>
                    <summary>
                      <h3>What you tried</h3>
                      <span className="chip" data-tone={recap ? (stops ? "warn" : "good") : undefined}>
                        {!recap ? "unavailable" : stops ? `stopped ${stops}×` : "nothing stopped"}
                      </span>
                    </summary>
                    <div className="fold-body">
                      {recap && recap.items.length ? (
                        <ul className="feed">
                          {recap.items.map((x, j) => (
                            <li key={`${x.message_id}-${j}`} data-decision={x.decision}>
                              <span className="chip" data-tone={TONE[x.decision]}>
                                {words(x.decision)}
                              </span>{" "}
                              at {words(x.stage)}
                              {x.rule_ids.length ? <> · {x.rule_ids.join(", ")}</> : null}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="muted">{recap ? "No checks ran." : "Recap not available."}</p>
                      )}
                      {recap?.diverts.map((d, j) => (
                        <p key={j} className="muted">
                          You tried <strong>{d.tool ?? words(d.stage)}</strong>: {d.attempted}. You got a decoy: <code>{d.decoy_shown}</code>
                        </p>
                      ))}
                    </div>
                  </details>
                ) : null}
                <div className="chat-actions">
                  {s.status === "active" ? (
                    <>
                      <Link className="btn-primary" href={`/arena/${s.id}`}>
                        Resume
                      </Link>
                      <CloseButton sessionId={s.id} />
                    </>
                  ) : (
                    <>
                      <Link className="btn-primary" href={`/classroom/sessions/${s.id}`}>
                        Review &amp; quiz
                      </Link>
                      <Link className="btn-alt" href={`/arena/${s.id}`}>
                        Chat
                      </Link>
                    </>
                  )}
                </div>
              </section>
            );
          })}
        </div>
      )}
    </main>
  );
}
