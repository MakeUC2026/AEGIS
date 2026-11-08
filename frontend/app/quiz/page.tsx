import Link from "next/link";

import { AccessDenied, QuizStatusPill, Unavailable } from "@/app/classroom/_components/Common";
import cls from "@/app/classroom/_components/classroom.module.css";
import { canView } from "@/app/classroom/_lib/access";
import { formatTime } from "@/app/classroom/_lib/format";
import { load } from "@/app/classroom/_lib/load";
import { requireViewer } from "@/app/classroom/_lib/viewer";

import styles from "./_components/quiz.module.css";
import type { ApiMineList } from "./_lib/adapt";
import { toListStatus } from "./_lib/status";

// Reads GET /api/quiz/mine: the student's own attempts, newest first.
export default async function Page() {
  const viewer = await requireViewer();
  if (!canView("quiz_list", viewer.roles)) {
    return <AccessDenied what="the student quiz list" home="/classroom" />;
  }
  const loaded = await load<ApiMineList>(["quiz", "mine"]);
  if (!loaded.ok) {
    return (
      <main>
        <div className={cls.head}>
          <h1>Quizzes</h1>
        </div>
        <Unavailable what="your quizzes" />
      </main>
    );
  }
  const items = loaded.data.items;
  const percents = items.flatMap((q) => (q.percent !== null ? [q.percent] : []));
  const latestDone = items.find((q) => q.status === "done" && q.percent !== null);
  return (
    <main>
      <div className={cls.head}>
        <h1>Quizzes</h1>
      </div>
      <p className={cls.lead}>
        Explain what happened in your own session. You can retake a quiz; the latest and the best score are both kept.
      </p>
      {percents.length > 0 ? (
        <p className={cls.count}>
          Latest {latestDone?.percent ?? "-"}% · Best {Math.max(...percents)}%
        </p>
      ) : null}
      {items.length === 0 ? (
        <p className={cls.empty}>
          No quizzes yet. Open one of your <Link href="/classroom">sessions</Link> and start a quiz.
        </p>
      ) : (
        <ul className={styles.list}>
          {items.map((q) => {
            const s = toListStatus(q.status);
            return (
              <li key={q.quiz_id} className={styles.card}>
                <div className={cls.actions} style={{ justifyContent: "space-between" }}>
                  <div>
                    <strong>Attempt {q.attempt_number}</strong>
                    <div className="muted">
                      {formatTime(q.created_at)} · <Link href={`/classroom/sessions/${encodeURIComponent(q.session_id)}`}>session</Link>
                    </div>
                    <div className={cls.actions}>
                      <QuizStatusPill status={s.pill} />
                      {q.percent !== null ? <span>{q.percent}%</span> : null}
                    </div>
                  </div>
                  <Link className="btn-alt" href={`/quiz/${encodeURIComponent(q.quiz_id)}`}>
                    {s.action}
                  </Link>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </main>
  );
}
