"use client";

import Link from "next/link";
import { useState } from "react";

import cls from "@/app/classroom/_components/classroom.module.css";

import { nextClassmateReply } from "../_lib/classmate-mock";
import { MOCK_KEY } from "../_lib/mock-key";
import type { MockQuestion } from "../_lib/mock";
import styles from "./quiz.module.css";

interface Chat {
  who: "me" | "them";
  text: string;
}

const MAX_ANSWER = 2000;

// SHELL: all state is local and the answers come from mock-key.ts. Phase C posts each answer to the
// API, which returns that question's result only (E-60, M4-X22). The first answer counts (M4-X20).
export function QuizRunner({ questions }: { questions: MockQuestion[] }) {
  const [step, setStep] = useState(0);
  const [picked, setPicked] = useState<Record<string, number>>({});
  const [choice, setChoice] = useState<number | null>(null);
  const [chats, setChats] = useState<Record<string, Chat[]>>({});
  const [finished, setFinished] = useState<Record<string, boolean>>({});
  const [draft, setDraft] = useState("");

  const q = questions[step];
  const last = step === questions.length - 1;

  function advance() {
    setChoice(null);
    setDraft("");
    setStep((s) => Math.min(s + 1, questions.length));
  }

  if (!q) {
    return (
      <div className={styles.card} role="status">
        <h2>All questions answered</h2>
        <p>In the real quiz this is where it is graded and your feedback is written.</p>
        <Link className="btn-primary" href="/quiz/qz-2">
          See a sample result
        </Link>
      </div>
    );
  }

  const progress = (
    <ol className={styles.progress} aria-label="Progress">
      {questions.map((x, i) => (
        <li key={x.id} aria-current={i === step ? "step" : undefined} className={i < step ? styles.done : undefined}>
          {i + 1}
        </li>
      ))}
    </ol>
  );

  if (q.type === "mcq") {
    const key = MOCK_KEY[q.id];
    const answered = q.id in picked;
    const shown = answered ? picked[q.id] : choice;
    return (
      <div>
        {progress}
        <div className={styles.card}>
          <span className={styles.topic}>
            Question {step + 1} of {questions.length} · {q.topic}
          </span>
          <fieldset className={styles.options}>
            <legend>{q.prompt}</legend>
            {(q.options ?? []).map((o, i) => {
              const state = answered ? (i === key.answerIndex ? styles.right : i === picked[q.id] ? styles.wrong : "") : "";
              return (
                <label key={o} className={`${styles.option} ${state}`}>
                  <input type="radio" name={q.id} checked={shown === i} disabled={answered} onChange={() => setChoice(i)} />
                  <span>{o}</span>
                </label>
              );
            })}
          </fieldset>
          {answered ? (
            <p className={styles.reveal} role="status">
              <strong>{picked[q.id] === key.answerIndex ? "Correct. " : "Not quite. "}</strong>
              {key.explanation}
            </p>
          ) : null}
          <div className={cls.actions}>
            {!answered ? (
              <button className="btn-primary" type="button" disabled={choice === null} onClick={() => choice !== null && setPicked((p) => ({ ...p, [q.id]: choice }))}>
                Check answer
              </button>
            ) : (
              <button className="btn-primary" type="button" onClick={advance}>
                {last ? "Finish" : "Next question"}
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  const chat = chats[q.id] ?? [{ who: "them" as const, text: q.prompt }];
  const answers = chat.filter((c) => c.who === "me").length;
  const over = finished[q.id] === true;

  function send() {
    const text = draft.trim();
    if (!text || over) return;
    const count = answers + 1;
    const reply = nextClassmateReply(count, text);
    setChats((c) => ({
      ...c,
      [q.id]: [...chat, { who: "me", text }, ...(over ? [] : [{ who: "them" as const, text: reply.text }])],
    }));
    setFinished((f) => ({ ...f, [q.id]: reply.finished }));
    setDraft("");
  }

  return (
    <div>
      {progress}
      <div className={styles.card}>
        <span className={styles.topic}>
          Question {step + 1} of {questions.length} · explain it to a classmate
        </span>
        <ul className={styles.chat} aria-label="Conversation with your classmate" aria-live="polite">
          {chat.map((c, i) => (
            <li key={i} className={`${styles.bubble} ${c.who === "me" ? styles.me : styles.them}`}>
              {c.text}
            </li>
          ))}
        </ul>
        {!over ? (
          <div className={styles.compose}>
            <label htmlFor="answer" className={styles.hint}>
              Your answer. Type &quot;done&quot; when you have nothing more to add.
            </label>
            <textarea id="answer" value={draft} maxLength={MAX_ANSWER} onChange={(e) => setDraft(e.target.value)} />
            <div className={cls.actions}>
              <button className="btn-primary" type="button" disabled={!draft.trim()} onClick={send}>
                Send
              </button>
              <span className={styles.hint}>
                {draft.length} / {MAX_ANSWER}
              </span>
            </div>
          </div>
        ) : (
          <div className={cls.actions}>
            <button className="btn-primary" type="button" onClick={advance}>
              {last ? "Finish" : "Next question"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
