import Link from "next/link";
import { notFound } from "next/navigation";

import { canAssignQuiz, canOpenSession } from "../../_lib/access";
import { AccessDenied, MockBadge, QuizStatusPill } from "../../_components/Common";
import { Decisions, Diverts, Forensics, HeldItems, Outcome, QuizScoreLine, Snapshot, Transcript } from "../../_components/DetailBlocks";
import styles from "../../_components/classroom.module.css";
import { mockDetail } from "../../_lib/mock";
import { formatTime } from "../../_lib/format";
import { requireViewer } from "../../_lib/viewer";

// Phase A shell: mock data. Phase B reads GET /api/classroom/sessions/{id}; the API enforces ownership.
export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const viewer = await requireViewer();
  const { id } = await params;
  const detail = mockDetail(id);
  if (!detail) notFound();
  if (!canOpenSession(viewer.roles, viewer.ownerKey, detail.row.studentId)) {
    return <AccessDenied what="this session" home="/classroom" />;
  }
  const r = detail.row;
  const assign = canAssignQuiz(viewer.roles);
  const own = viewer.kind === "student";
  return (
    <main>
      <Link className={styles.back} href="/classroom">
        &larr; All sessions
      </Link>
      <div className={styles.head}>
        <h1>
          {r.studentName}, {r.levelName}
        </h1>
        <MockBadge />
      </div>
      <p className={styles.lead}>
        {r.mode} mode, started {formatTime(r.startedAt)}, {r.status}.
      </p>
      <div className={styles.grid}>
        <Outcome d={detail} />
        <Snapshot d={detail} />
        <Transcript d={detail} />
        <Decisions d={detail} />
        <HeldItems d={detail} />
        <Forensics d={detail} />
        <Diverts d={detail} />
        <section className={`${styles.block} ${styles.wide}`} aria-labelledby="h-quiz">
          <h2 id="h-quiz">Quiz</h2>
          <div className={styles.actions}>
            <QuizStatusPill status={r.quizStatus} />
            {r.quizStatus === "done" ? (
              <span>
                Score <QuizScoreLine points={r.quizPoints} />
              </span>
            ) : null}
            {r.quizId ? (
              <Link className="btn-alt" href={`/quiz/${r.quizId}`}>
                {r.quizStatus === "done" ? "View result" : own ? "Resume quiz" : "View quiz"}
              </Link>
            ) : null}
            {r.quizStatus === "assigned" ? <span className="muted">Assigned. Waiting for the student to start.</span> : null}
            {!r.quizId && r.quizStatus === "not_taken" && (assign || own) ? (
              <button className="button" type="button" disabled title="Wired up in Phase C">
                {assign ? "Assign quiz" : "Start quiz"}
              </button>
            ) : null}
          </div>
          {viewer.kind === "firewall_admin" ? <p className="muted">Read-only view: firewall admins cannot assign quizzes.</p> : null}
        </section>
      </div>
    </main>
  );
}
