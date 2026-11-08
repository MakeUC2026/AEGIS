import { ITEM_TITLES, type ItemKey } from "@/app/quiz/_lib/rubric";

import { MOCK_INSIGHTS as I } from "../_lib/mock-class";
import styles from "./classroom.module.css";

function Bars({ rows, scale }: { rows: readonly { label: string; value: number }[]; scale?: number }) {
  const max = scale ?? Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className={styles.bars}>
      {rows.map((r) => (
        <li key={r.label}>
          <span>{r.label}</span>
          <span className={styles.bar} aria-hidden="true">
            <i style={{ width: `${(r.value / max) * 100}%` }} />
          </span>
          <span className={styles.num}>{r.value}</span>
        </li>
      ))}
    </ul>
  );
}

export function InsightsView() {
  return (
    <div className={styles.grid}>
      <section className={`${styles.block} ${styles.wide}`} aria-labelledby="i-overview">
        <h2 id="i-overview">Class overview</h2>
        <div className={styles.stats}>
          <div className={styles.stat}><strong>{I.overview.students}</strong><span className="muted">students</span></div>
          <div className={styles.stat}><strong>{I.overview.sessions}</strong><span className="muted">sessions</span></div>
          <div className={styles.stat}><strong>{I.overview.sessionsPerStudent}</strong><span className="muted">per student</span></div>
          <div className={styles.stat}><strong>{I.overview.activeToday}</strong><span className="muted">active today</span></div>
        </div>
      </section>

      <section className={styles.block} aria-labelledby="i-outcomes">
        <h2 id="i-outcomes">Outcomes per level</h2>
        <table className={styles.simpleTable}>
          <thead>
            <tr><th scope="col">Level</th><th scope="col">Obtained</th><th scope="col">Not yet</th></tr>
          </thead>
          <tbody>
            {I.outcomes.map((o) => (
              <tr key={o.levelName}>
                <th scope="row">{o.levelName}</th>
                <td>{o.obtained.join(", ") || "-"}</td>
                <td>{o.notYet.join(", ") || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className={styles.block} aria-labelledby="i-defense">
        <h2 id="i-defense">Defense activity</h2>
        <p className={styles.sub}>Rules fired most</p>
        <Bars rows={I.defense.topRules.map((r) => ({ label: r.id, value: r.count }))} />
        <p className={styles.sub} style={{ marginTop: 16 }}>Decisions per mode</p>
        <table className={styles.simpleTable}>
          <thead>
            <tr><th scope="col">Mode</th><th scope="col">Allow</th><th scope="col">Review</th><th scope="col">Deny</th><th scope="col">Divert</th></tr>
          </thead>
          <tbody>
            {I.defense.decisionsPerMode.map((m) => (
              <tr key={m.mode}>
                <th scope="row">{m.mode}</th>
                <td className={styles.num}>{m.allow}</td>
                <td className={styles.num}>{m.review}</td>
                <td className={styles.num}>{m.deny}</td>
                <td className={styles.num}>{m.divert}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className={styles.sub} style={{ marginTop: 12 }}>Diverts in total: {I.defense.divertCount}</p>
      </section>

      <section className={styles.block} aria-labelledby="i-families">
        <h2 id="i-families">Attack families</h2>
        <Bars rows={I.attackFamilies.map((f) => ({ label: f.family, value: f.count }))} />
      </section>

      <section className={styles.block} aria-labelledby="i-patterns">
        <h2 id="i-patterns">Risky patterns</h2>
        <Bars rows={I.riskyPatterns.map((p) => ({ label: p.id, value: p.count }))} />
      </section>

      <section className={`${styles.block} ${styles.wide}`} aria-labelledby="i-quiz">
        <h2 id="i-quiz">Quiz</h2>
        <div className={styles.stats}>
          <div className={styles.stat}><strong>{I.quiz.taken}</strong><span className="muted">taken</span></div>
          <div className={styles.stat}><strong>{I.quiz.open}</strong><span className="muted">open</span></div>
          <div className={styles.stat}><strong>{I.quiz.averagePercent}%</strong><span className="muted">average score</span></div>
        </div>
        <p className={styles.sub} style={{ marginTop: 16 }}>Rubric items the class scores lowest on (average out of 3)</p>
        <Bars scale={3} rows={I.quiz.lowestItems.map((x) => ({ label: ITEM_TITLES[x.key as ItemKey], value: x.average }))} />
      </section>
    </div>
  );
}
