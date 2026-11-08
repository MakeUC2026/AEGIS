import Link from "next/link";

import { formatScore, formatTime, outcomeLabel } from "../_lib/format";
import type { SessionRow } from "../_lib/types";
import { Pill, QuizStatusPill } from "./Common";
import styles from "./classroom.module.css";

// Teacher / admin session list as cards. The whole card is the link (no nested controls).
export function SessionCards({ rows }: { rows: readonly SessionRow[] }) {
  if (rows.length === 0) {
    return <p className={styles.empty}>No sessions match these filters.</p>;
  }
  return (
    <ul className="card-grid" style={{ listStyle: "none", margin: 0, padding: 0 }} aria-label="Sessions">
      {rows.map((r) => (
        <li key={r.id}>
          <Link href={`/classroom/sessions/${r.id}`} className="entry-card" style={{ minHeight: 0, "--tone": r.secretObtained ? "var(--danger)" : "var(--accent)" } as React.CSSProperties}>
            <div className={styles.actions} style={{ justifyContent: "space-between" }}>
              <span className="mode-chip" data-mode={r.mode}>
                {r.mode}
              </span>
              {r.adminTest ? <Pill tone="info">Admin test</Pill> : r.status === "active" ? <Pill tone="info">Active</Pill> : null}
            </div>
            <h2>{r.studentName}</h2>
            <p>
              {r.levelName} · {formatTime(r.startedAt)}
            </p>
            <div className={styles.actions}>
              <Pill tone={r.secretObtained ? "bad" : "good"}>{outcomeLabel(r.secretObtained)}</Pill>
              {r.divertedCount ? <Pill tone="warn">{r.divertedCount} diverted</Pill> : null}
              <Pill tone="quiet">top score {r.maxSentinelScore ?? "–"}</Pill>
            </div>
            <div className={styles.actions}>
              <QuizStatusPill status={r.quizStatus} />
              {r.quizPoints !== null ? <span className="muted">{formatScore(r.quizPoints)}</span> : null}
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}
