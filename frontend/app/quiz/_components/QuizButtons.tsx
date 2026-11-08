"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import cls from "@/app/classroom/_components/classroom.module.css";
import { ApiError, apiFetch } from "@/lib/api";

import { errorMessage } from "../_lib/adapt";
import styles from "./quiz.module.css";

function failure(err: unknown): string {
  return err instanceof ApiError ? errorMessage(err.status, err.detail) : errorMessage(0, "");
}

interface Started {
  quiz_id: string;
}

// Student starts (or resumes) a quiz on their own session. Generation can take a while.
export function StartQuizButton({ sessionId, label = "Start quiz" }: { sessionId: string; label?: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const out = await apiFetch<Started>("quiz/quizzes", { method: "POST", json: { session_id: sessionId } });
      router.push(`/quiz/${encodeURIComponent(out.quiz_id)}`);
    } catch (err) {
      setError(failure(err));
      setBusy(false);
    }
  }

  return (
    <div>
      <button className="btn-primary" type="button" disabled={busy} onClick={start}>
        {busy ? "Making your quiz..." : label}
      </button>
      <p role="status" className="muted">
        {busy ? "This takes up to a minute." : null}
      </p>
      {error ? (
        <p role="alert" className={styles.error}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

// Teacher assigns a quiz to the session's student. Nothing is generated until the student starts.
export function AssignQuizButton({ sessionId }: { sessionId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function assign() {
    setBusy(true);
    setError(null);
    try {
      await apiFetch("quiz/assign", { method: "POST", json: { session_id: sessionId } });
      router.refresh();
    } catch (err) {
      setError(failure(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <button className="btn-primary" type="button" disabled={busy} onClick={assign}>
        {busy ? "Assigning..." : "Assign quiz"}
      </button>
      {error ? (
        <p role="alert" className={styles.error}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function RegradeButton({ quizId }: { quizId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function regrade() {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`quiz/quizzes/${encodeURIComponent(quizId)}/regrade`, { method: "POST" });
      router.refresh();
    } catch (err) {
      setError(failure(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className={cls.actions}>
        <button className="btn-primary" type="button" disabled={busy} onClick={regrade}>
          {busy ? "Grading..." : "Grade again"}
        </button>
      </div>
      {error ? (
        <p role="alert" className={styles.error}>
          {error}
        </p>
      ) : null}
    </div>
  );
}
