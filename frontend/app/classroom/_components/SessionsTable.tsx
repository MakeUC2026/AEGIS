import Link from "next/link";

import { formatScore, formatTime, outcomeLabel } from "../_lib/format";
import type { SessionRow } from "../_lib/types";
import { Pill, QuizStatusPill } from "./Common";
import styles from "./classroom.module.css";

export function SessionsTable({ rows }: { rows: readonly SessionRow[] }) {
  if (rows.length === 0) {
    return <p className={styles.empty}>No sessions match these filters.</p>;
  }
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <caption className={styles.srOnly}>
          Sessions
        </caption>
        <thead>
          <tr>
            <th scope="col">Student</th>
            <th scope="col">Level</th>
            <th scope="col">Mode</th>
            <th scope="col">Secret</th>
            <th scope="col">Diverted</th>
            <th scope="col">Top score</th>
            <th scope="col">Started</th>
            <th scope="col">Quiz</th>
            <th scope="col">Quiz score</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td data-label="Student">
                <Link className={styles.rowLink} href={`/classroom/sessions/${r.id}`}>
                  {r.studentName}
                </Link>
                {r.adminTest ? (
                  <>
                    {" "}
                    <Pill tone="info">Admin test</Pill>
                  </>
                ) : null}
              </td>
              <td data-label="Level">{r.levelName}</td>
              <td data-label="Mode">{r.mode}</td>
              <td data-label="Secret">
                <Pill tone={r.secretObtained ? "bad" : "good"}>{outcomeLabel(r.secretObtained)}</Pill>
              </td>
              <td data-label="Diverted" className={styles.num}>
                {r.divertedCount}
              </td>
              <td data-label="Top score" className={styles.num}>
                {r.maxSentinelScore ?? "-"}
              </td>
              <td data-label="Started">{formatTime(r.startedAt)}</td>
              <td data-label="Quiz">
                <QuizStatusPill status={r.quizStatus} />
              </td>
              <td data-label="Quiz score" className={styles.num}>
                {formatScore(r.quizPoints)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
