import Link from "next/link";
import { notFound } from "next/navigation";

import { AccessDenied, QuizStatusPill, Unavailable } from "@/app/classroom/_components/Common";
import cls from "@/app/classroom/_components/classroom.module.css";
import { load } from "@/app/classroom/_lib/load";
import { requireViewer } from "@/app/classroom/_lib/viewer";

import { StartQuizButton } from "../_components/QuizButtons";
import { QuizResultView } from "../_components/QuizResultView";
import { QuizRunner } from "../_components/QuizRunner";
import { toQuizRun, toResultView, type ApiQuizView, type ApiResult } from "../_lib/adapt";
import { toListStatus } from "../_lib/status";

// Owner student and teacher only; firewall admins have no quiz screens (the API answers 403).
export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const viewer = await requireViewer();
  const { id } = await params;
  const home = viewer.kind === "student" ? "/quiz" : "/classroom";
  const loaded = await load<ApiQuizView>(["quiz", "quizzes", id]);
  if (!loaded.ok) {
    if (loaded.reason === "notfound") notFound();
    return loaded.reason === "forbidden" ? (
      <AccessDenied what="this quiz" home={home} />
    ) : (
      <main>
        <Unavailable what="the quiz" />
      </main>
    );
  }
  const run = toQuizRun(loaded.data);
  const teacher = viewer.kind !== "student"; // staff (teacher or admin) read, never act
  const finished = run.status === "done" || run.status === "grading_failed";
  const resultLoaded = finished ? await load<ApiResult>(["quiz", "quizzes", id, "result"]) : null;
  const sessionHref = `/classroom/sessions/${encodeURIComponent(run.sessionId)}`;

  let body: React.ReactNode;
  if (resultLoaded) {
    body = resultLoaded.ok ? (
      <QuizResultView result={toResultView(resultLoaded.data)} canRegrade={!teacher} />
    ) : (
      <Unavailable what="the result" />
    );
  } else if (run.status === "assigned") {
    body = teacher ? (
      <p className="muted">Assigned. Waiting for the student to start.</p>
    ) : (
      <div className={cls.block}>
        <h2>Your teacher assigned this quiz</h2>
        <p>It is made from your own session. It takes a few minutes.</p>
        <StartQuizButton sessionId={run.sessionId} />
      </div>
    );
  } else if (teacher) {
    const mcq = run.questions.filter((q) => q.type === "mcq");
    const done = mcq.filter((q) => q.id in run.answered).length;
    body = (
      <p className="muted">
        In progress: {done} of {mcq.length} multiple-choice questions answered. The grade appears when the student finishes.
      </p>
    );
  } else {
    body = <QuizRunner run={run} />;
  }

  const pill = toListStatus(run.status).pill;
  return (
    <main>
      <Link className={cls.back} href={teacher ? sessionHref : "/quiz"}>
        &larr; {teacher ? "Back to the session" : "All quizzes"}
      </Link>
      <div className={cls.head}>
        <h1>{finished ? "Quiz result" : "Quiz"}</h1>
      </div>
      <div className={cls.actions}>
        <QuizStatusPill status={pill} />
        <span className="muted">Attempt {run.attempt}</span>
        {!teacher ? (
          <Link href={sessionHref}>Your session</Link>
        ) : null}
      </div>
      {body}
    </main>
  );
}
