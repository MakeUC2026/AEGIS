"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import cls from "@/app/classroom/_components/classroom.module.css";
import { ApiError, apiFetch } from "@/lib/api";

import {
  chatClosed,
  errorMessage,
  firstUnansweredStep,
  type ChatLine,
  type QuizRun,
} from "../_lib/adapt";
import styles from "./quiz.module.css";

const MAX_ANSWER = 2000;
const MAX_FOLLOW_UPS = 3;

interface AnswerOut {
  chosen_index: number;
  correct: boolean;
  explanation: string;
}

interface TurnOut {
  accepted: boolean;
  reply: string | null;
  closed: boolean;
}

function failure(err: unknown): string {
  return err instanceof ApiError ? errorMessage(err.status, err.detail) : errorMessage(0, "");
}

// Every answer goes to the API. The API returns correctness and that question's explanation only
// once it is answered (E-60, M4-X22); the first answer counts (M4-X20), so a repeat is not sent twice.
export function QuizRunner({ run }: { run: QuizRun }) {
  const router = useRouter();
  const base = `quiz/quizzes/${encodeURIComponent(run.quizId)}`;
  const [step, setStep] = useState(() => firstUnansweredStep(run));
  const [answered, setAnswered] = useState(run.answered);
  const [chats, setChats] = useState<Record<string, ChatLine[]>>(run.chats);
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const [choice, setChoice] = useState<number | null>(null);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [grading, setGrading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const q = run.questions[step];
  const last = step >= run.questions.length - 1;

  function advance() {
    setChoice(null);
    setDraft("");
    setError(null);
    setStep((s) => s + 1);
  }

  async function finish() {
    setGrading(true);
    setError(null);
    try {
      await apiFetch(`${base}/finish`, { method: "POST" });
      router.refresh();
    } catch (err) {
      setError(failure(err));
      setGrading(false);
    }
  }

  async function check(question: string) {
    if (choice === null || busy) return;
    setBusy(true);
    setError(null);
    try {
      const out = await apiFetch<AnswerOut>(`${base}/questions/${encodeURIComponent(question)}/answer`, {
        method: "POST",
        json: { index: choice },
      });
      setAnswered((a) => ({
        ...a,
        [question]: { chosenIndex: out.chosen_index, correct: out.correct, explanation: out.explanation },
      }));
    } catch (err) {
      setError(failure(err));
    } finally {
      setBusy(false);
    }
  }

  async function send(question: string, prompt: string, existing: ChatLine[]) {
    const text = draft.trim();
    if (!text || busy) return;
    setBusy(true);
    setError(null);
    try {
      const out = await apiFetch<TurnOut>(`${base}/turns`, { method: "POST", json: { question_id: question, text } });
      if (!out.accepted) {
        setClosed((c) => ({ ...c, [question]: true }));
        return;
      }
      const lines: ChatLine[] = existing.length ? existing : [{ who: "them", text: prompt }];
      setChats((c) => ({
        ...c,
        [question]: [...lines, { who: "me", text }, ...(out.reply ? [{ who: "them" as const, text: out.reply }] : [])],
      }));
      if (out.closed) setClosed((c) => ({ ...c, [question]: true }));
      setDraft("");
    } catch (err) {
      setError(failure(err));
    } finally {
      setBusy(false);
    }
  }

  if (grading) {
    return (
      <div className={styles.card} role="status" aria-live="polite">
        <h2>Grading your answers</h2>
        <p>Your classmate is reading your explanations. This can take up to a minute.</p>
      </div>
    );
  }

  if (!q) {
    return (
      <div className={styles.card}>
        <h2>All questions answered</h2>
        <p>Finish to get your score and feedback.</p>
        {error ? <p role="alert" className={styles.error}>{error}</p> : null}
        <div className={cls.actions}>
          <button className="btn-primary" type="button" onClick={finish}>
            Finish and grade
          </button>
        </div>
      </div>
    );
  }

  const progress = (
    <ol className={styles.progress} aria-label="Progress">
      {run.questions.map((x, i) => (
        <li key={x.id} aria-current={i === step ? "step" : undefined} className={i < step ? styles.done : undefined}>
          {i + 1}
        </li>
      ))}
    </ol>
  );

  const errorLine = error ? (
    <p role="alert" className={styles.error}>
      {error}
    </p>
  ) : null;

  if (q.type === "mcq") {
    const result = answered[q.id];
    const shown = result ? result.chosenIndex : choice;
    return (
      <div>
        {progress}
        <div className={styles.card}>
          <span className={styles.topic}>
            Question {step + 1} of {run.questions.length} · {q.topic}
          </span>
          <fieldset className={styles.options}>
            <legend>{q.prompt}</legend>
            {q.options.map((o, i) => {
              const state = result && i === result.chosenIndex ? (result.correct ? styles.right : styles.wrong) : "";
              return (
                <label key={`${i}-${o}`} className={`${styles.option} ${state}`}>
                  <input type="radio" name={q.id} checked={shown === i} disabled={Boolean(result) || busy} onChange={() => setChoice(i)} />
                  <span>{o}</span>
                </label>
              );
            })}
          </fieldset>
          {result ? (
            <p className={styles.reveal} role="status">
              <strong>{result.correct ? "Correct. " : "Not quite. "}</strong>
              {result.explanation}
            </p>
          ) : null}
          {errorLine}
          <div className={cls.actions}>
            {!result ? (
              <button className="btn-primary" type="button" disabled={choice === null || busy} onClick={() => check(q.id)}>
                {busy ? "Checking..." : "Check answer"}
              </button>
            ) : (
              <button className="btn-primary" type="button" onClick={advance}>
                {last ? "Continue" : "Next question"}
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  const stored = chats[q.id] ?? [];
  const chat: ChatLine[] = stored.length ? stored : [{ who: "them", text: q.prompt }];
  const over = closed[q.id] === true || chatClosed(stored, MAX_FOLLOW_UPS);
  return (
    <div>
      {progress}
      <div className={styles.card}>
        <span className={styles.topic}>
          Question {step + 1} of {run.questions.length} · explain it to a classmate
        </span>
        <ul className={styles.chat} aria-label="Conversation with your classmate" aria-live="polite">
          {chat.map((c, i) => (
            <li key={i} className={`${styles.bubble} ${c.who === "me" ? styles.me : styles.them}`}>
              {c.text}
            </li>
          ))}
        </ul>
        {errorLine}
        {!over ? (
          <div className={styles.compose}>
            <label htmlFor="answer" className={styles.hint}>
              Your answer. Type &quot;done&quot; when you have nothing more to add.
            </label>
            <textarea id="answer" value={draft} maxLength={MAX_ANSWER} disabled={busy} onChange={(e) => setDraft(e.target.value)} />
            <div className={cls.actions}>
              <button className="btn-primary" type="button" disabled={!draft.trim() || busy} onClick={() => send(q.id, q.prompt, stored)}>
                {busy ? "Sending..." : "Send"}
              </button>
              <span className={styles.hint}>
                {draft.length} / {MAX_ANSWER}
              </span>
            </div>
          </div>
        ) : (
          <div className={cls.actions}>
            <button className="btn-primary" type="button" onClick={advance}>
              {last ? "Continue" : "Next question"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
