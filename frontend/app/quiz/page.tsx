import Link from "next/link";

import { AccessDenied, MockBadge } from "@/app/classroom/_components/Common";
import cls from "@/app/classroom/_components/classroom.module.css";
import { canView } from "@/app/classroom/_lib/access";
import { formatScore } from "@/app/classroom/_lib/format";
import { requireViewer } from "@/app/classroom/_lib/viewer";

import styles from "./_components/quiz.module.css";
import { MOCK_QUIZZES } from "./_lib/mock";

// Phase A shell: mock data. Phase C reads GET /api/quiz/mine.
export default async function Page() {
  const viewer = await requireViewer();
  if (!canView("quiz_list", viewer.roles)) {
    return <AccessDenied what="the student quiz list" home="/classroom" />;
  }
  const mine = MOCK_QUIZZES.filter((q) => q.studentId === viewer.ownerKey);
  const scores = mine.flatMap((q) => (q.result ? [q.result.total] : []));
  return (
    <main>
      <div className={cls.head}>
        <h1>Quizzes</h1>
        <MockBadge />
      </div>
      <p className={cls.lead}>
        Explain what happened in your own session. You can retake a quiz; the latest and the best score are both kept.
      </p>
      {scores.length > 0 ? (
        <p className={cls.count}>
          Latest {formatScore(scores[scores.length - 1])} · Best {formatScore(Math.max(...scores))}
        </p>
      ) : null}
      {mine.length === 0 ? (
        <p className={cls.empty}>
          No quizzes yet. Open one of your <Link href="/arena/sessions">sessions</Link> and start a quiz.
        </p>
      ) : (
        <ul className={styles.list}>
          {mine.map((q) => (
            <li key={q.id} className={styles.card}>
              <div className={cls.actions} style={{ justifyContent: "space-between" }}>
                <div>
                  <strong>Session {q.sessionId}</strong>
                  <div className="muted">
                    {q.status === "done" && q.result ? `Score ${formatScore(q.result.total)}` : "In progress"}
                  </div>
                </div>
                <Link className="btn-alt" href={`/quiz/${q.id}`}>
                  {q.status === "done" ? "View result" : "Resume"}
                </Link>
              </div>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
