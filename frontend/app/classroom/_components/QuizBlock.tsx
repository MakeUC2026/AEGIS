import Link from "next/link";

import { AssignQuizButton, StartQuizButton } from "@/app/quiz/_components/QuizButtons";
import type { AttemptsView } from "@/app/quiz/_lib/adapt";
import { toListStatus } from "@/app/quiz/_lib/status";

import { formatTime } from "../_lib/format";
import type { SessionRow, ViewerKind } from "../_lib/types";
import { QuizStatusPill } from "./Common";
import styles from "./classroom.module.css";

// Quiz block on session detail: attempts (latest and best) and the action the viewer may take.
// Teachers assign, the owning student starts or resumes, firewall admins only look (I-4: the API
// checks the same rules).
export function QuizBlock({
  sessionId,
  kind,
  row,
  attempts,
}: {
  sessionId: string;
  kind: ViewerKind;
  row: SessionRow;
  attempts: AttemptsView | null;
}) {
  const rows = attempts?.rows ?? [];
  const open = rows.find((a) => a.status === "in_progress" || a.status === "assigned");
  return (
    <details className={`${styles.block} ${styles.wide}`} open>
      <summary>
        <h2 id="h-quiz">Quiz</h2>
      </summary>
      <div className={styles.actions}>
        <QuizStatusPill status={row.quizStatus} />
        {attempts && (attempts.latest !== null || attempts.best !== null) ? (
          <span>
            Latest {attempts.latest ?? "-"}% · Best {attempts.best ?? "-"}%
          </span>
        ) : null}
      </div>
      {rows.length > 0 ? (
        <ul className={styles.attempts} aria-label="Quiz attempts">
          {rows.map((a) => {
            const s = toListStatus(a.status);
            return (
              <li key={a.quizId}>
                <span>
                  Attempt {a.attempt} · {formatTime(a.createdAt)}
                </span>
                <QuizStatusPill status={s.pill} />
                <span className={styles.num}>{a.percent !== null ? `${a.percent}%` : "-"}</span>
                <Link className="btn-alt" href={`/quiz/${encodeURIComponent(a.quizId)}`}>
                  {a.status === "done" ? "View result" : kind !== "student" ? "View" : s.action}
                </Link>
              </li>
            );
          })}
        </ul>
      ) : null}
      {kind === "teacher" && !open ? <AssignQuizButton sessionId={sessionId} /> : null}
      {kind === "teacher" && open ? <p className="muted">An attempt is open, so a new quiz cannot be assigned yet.</p> : null}
      {kind === "student" ? (
        <StartQuizButton
          sessionId={sessionId}
          label={open ? "Resume quiz" : rows.length > 0 ? "Retake quiz" : "Start quiz"}
        />
      ) : null}
      {kind === "firewall_admin" ? <p className="muted">Read-only: teachers assign quizzes.</p> : null}
      {kind === "student" && rows.length === 0 ? (
        <p className="muted">Diverts and the firewall analysis open up after you take the quiz.</p>
      ) : null}
      {kind === "student" && rows.length > 0 ? (
        <p className="muted">
          The firewall analysis is open. See what stopped you under <Link href="/arena/sessions">My sessions</Link>.
        </p>
      ) : null}
    </details>
  );
}
