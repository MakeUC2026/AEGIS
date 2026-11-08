import Link from "next/link";
import { notFound } from "next/navigation";

import { AccessDenied, Unavailable } from "../../_components/Common";
import { Decisions, Diverts, Forensics, HeldItems, Outcome, Snapshot, Transcript } from "../../_components/DetailBlocks";
import styles from "../../_components/classroom.module.css";
import { toDetail, type ApiDetail } from "../../_lib/adapt";
import { formatTime } from "../../_lib/format";
import { load } from "../../_lib/load";
import { requireViewer } from "../../_lib/viewer";
import { QuizBlock } from "../../_components/QuizBlock";
import { toAttempts, type ApiAttemptList } from "@/app/quiz/_lib/adapt";

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
  const attemptsLoaded = await load<ApiAttemptList>(["quiz", "sessions", id, "attempts"]);
  const attempts = attemptsLoaded?.ok ? toAttempts(attemptsLoaded.data) : null;
  return (
    <main>
      <Link className={styles.back} href={viewer.kind === "student" ? "/arena/sessions" : "/classroom"}>
        &larr; {viewer.kind === "student" ? "My sessions" : "All sessions"}
      </Link>
      <div className="page-head">
        <div>
          <p className="eyebrow learn">Classroom</p>
          <h1>
            {viewer.kind === "student" ? r.levelName : `${r.studentName}, ${r.levelName}`}
          </h1>
          <p className="muted">
            <span className="mode-chip" data-mode={r.mode}>{r.mode}</span> · {formatTime(r.startedAt)} · {r.status}
            {r.adminTest ? " · admin test" : ""}
          </p>
        </div>
      </div>
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
        <QuizBlock sessionId={id} kind={viewer.kind} row={r} attempts={attempts} />
      </div>
    </main>
  );
}
