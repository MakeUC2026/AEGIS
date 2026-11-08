import Link from "next/link";
import { notFound } from "next/navigation";

import { AccessDenied, MockBadge } from "@/app/classroom/_components/Common";
import cls from "@/app/classroom/_components/classroom.module.css";
import { requireViewer } from "@/app/classroom/_lib/viewer";

import { QuizResultView } from "../_components/QuizResultView";
import { QuizRunner } from "../_components/QuizRunner";
import { mockQuiz } from "../_lib/mock";

// Phase A shell: mock data. Owner student and teacher only; firewall admins have no quiz screens.
export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const viewer = await requireViewer();
  const { id } = await params;
  const quiz = mockQuiz(id);
  if (!quiz) notFound();
  const allowed = viewer.kind === "teacher" || (viewer.kind === "student" && viewer.ownerKey === quiz.studentId);
  if (!allowed) return <AccessDenied what="this quiz" home={viewer.kind === "student" ? "/quiz" : "/classroom"} />;
  const teacher = viewer.kind === "teacher";
  return (
    <main>
      <Link className={cls.back} href={teacher ? `/classroom/sessions/${quiz.sessionId}` : "/quiz"}>
        &larr; {teacher ? "Back to the session" : "All quizzes"}
      </Link>
      <div className={cls.head}>
        <h1>{quiz.status === "done" ? "Quiz result" : "Quiz"}</h1>
        <MockBadge />
      </div>
      <p className={cls.lead}>
        {quiz.studentName}, session {quiz.sessionId}.
      </p>
      {quiz.status === "in_progress" && !teacher ? (
        <QuizRunner questions={quiz.questions} />
      ) : (
        <QuizResultView quiz={quiz} showItems={teacher} />
      )}
    </main>
  );
}
