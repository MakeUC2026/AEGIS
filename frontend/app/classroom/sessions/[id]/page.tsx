import Link from "next/link";
import { notFound } from "next/navigation";

import { AccessDenied, QuizStatusPill, Unavailable } from "../../_components/Common";
import { Decisions, Diverts, Forensics, HeldItems, Outcome, QuizScoreLine, Snapshot, Transcript } from "../../_components/DetailBlocks";
import styles from "../../_components/classroom.module.css";
import { toDetail, type ApiDetail } from "../../_lib/adapt";
import { canAssignQuiz } from "../../_lib/access";
import { formatTime } from "../../_lib/format";
import { load } from "../../_lib/load";
import { requireViewer } from "../../_lib/viewer";

// Reads GET /api/classroom/sessions/{id}. The API enforces ownership (403) and gives a student
// only their transcript and outcome; the staff-only blocks are simply not rendered for them.
export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const viewer = await requireViewer();
  const { id } = await params;
  const loaded = await load<ApiDetail>(["classroom", "sessions", id]);
  if (!loaded.ok) {
    if (loaded.reason === "notfound") notFound();
    return loaded.reason === "forbidden" ? (
      <AccessDenied what="this session" home="/classroom" />
    ) : (
      <main>
        <Unavailable what="the session" />
      </main>
    );
  }
  const { staff, hasConfig, view: detail } = toDetail(loaded.data);
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
      </div>
      <p className={styles.lead}>
        {r.mode} mode, started {formatTime(r.startedAt)}, {r.status}.
        {r.adminTest ? " Admin test session." : ""}
      </p>
      <div className={styles.grid}>
        <Outcome d={detail} />
        {staff && hasConfig ? <Snapshot d={detail} /> : null}
        <Transcript d={detail} />
        {staff ? (
          <>
            <Decisions d={detail} />
            <HeldItems d={detail} />
            <Forensics d={detail} />
            <Diverts d={detail} />
          </>
        ) : null}
        <section className={`${styles.block} ${styles.wide}`} aria-labelledby="h-quiz">
          <h2 id="h-quiz">Quiz</h2>
          <div className={styles.actions}>
            <QuizStatusPill status={r.quizStatus} />
            {r.quizStatus === "done" ? (
              <span>
                Score <QuizScoreLine points={r.quizPoints} />
              </span>
            ) : null}
            {r.quizStatus === "assigned" ? <span className="muted">Assigned. Waiting for the student to start.</span> : null}
            {r.quizStatus === "not_taken" && (assign || own) ? (
              <button className="button" type="button" disabled title="The quiz API arrives in phase C">
                {assign ? "Assign quiz" : "Start quiz"}
              </button>
            ) : null}
          </div>
          {viewer.kind === "firewall_admin" ? <p className="muted">Read-only view: firewall admins cannot assign quizzes.</p> : null}
          {own ? <p className="muted">Diverts and the firewall analysis open up after you take the quiz.</p> : null}
        </section>
      </div>
    </main>
  );
}
