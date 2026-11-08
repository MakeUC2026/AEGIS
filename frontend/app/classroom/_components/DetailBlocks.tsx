import { formatScore, formatTime, outcomeLabel } from "../_lib/format";
import type { SessionDetail } from "../_lib/types";
import { Pill } from "./Common";
import styles from "./classroom.module.css";

// Everything below renders strings as React text nodes, so HTML in a transcript stays inert (M4-X19).
// No raw-HTML sinks are used anywhere in this folder.

export function Transcript({ d }: { d: SessionDetail }) {
  return (
    <section className={`${styles.block} ${styles.wide}`} aria-labelledby="h-transcript">
      <h2 id="h-transcript">Transcript</h2>
      <ol className={styles.log}>
        {d.transcript.map((t) => (
          <li key={t.id} className={`${styles.msg} ${styles[t.speaker]} ${t.isDecoy ? styles.decoy : ""}`}>
            <div className={styles.who}>
              <span>{t.speaker}</span>
              {t.status ? <Pill tone={t.status === "blocked" ? "bad" : "quiet"}>{t.status.replace("_", " ")}</Pill> : null}
              {t.isDecoy ? <Pill tone="warn">Decoy shown to the student</Pill> : null}
            </div>
            {t.text}
          </li>
        ))}
      </ol>
    </section>
  );
}

export function Decisions({ d }: { d: SessionDetail }) {
  return (
    <section className={`${styles.block} ${styles.wide}`} aria-labelledby="h-decisions">
      <h2 id="h-decisions">Decisions</h2>
      <div className={styles.scroll}>
        <table className={`${styles.simpleTable} ${styles.wideTable}`}>
          <thead>
            <tr>
              <th scope="col">Stage</th>
              <th scope="col">Decision</th>
              <th scope="col">Score</th>
              <th scope="col">Breakdown</th>
              <th scope="col">Rules</th>
              <th scope="col">Risky patterns</th>
            </tr>
          </thead>
          <tbody>
            {d.decisions.map((x) => (
              <tr key={x.id}>
                <td>{x.stage}</td>
                <td>
                  <Pill tone={x.decision === "allow" ? "good" : x.decision === "divert" ? "warn" : "bad"}>{x.decision}</Pill>
                </td>
                <td className={styles.num}>{x.score}</td>
                <td>
                  {Object.entries(x.breakdown)
                    .map(([k, v]) => `${k}: ${v ?? "did not run"}`)
                    .join(", ")}
                </td>
                <td>{x.rules.join(", ") || "-"}</td>
                <td>{x.riskyPatterns.join(", ") || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function Snapshot({ d }: { d: SessionDetail }) {
  const c = d.config;
  return (
    <section className={styles.block} aria-labelledby="h-config">
      <h2 id="h-config">Configuration snapshot</h2>
      <p className={styles.sub}>The session is pinned to this setup. Later changes do not affect it.</p>
      <dl className={styles.kv}>
        <dt>Level version</dt>
        <dd>{c.levelVersion}</dd>
        <dt>Mode</dt>
        <dd>{c.mode}</dd>
        <dt>Rule version</dt>
        <dd>{c.ruleVersion}</dd>
        <dt>Risky pattern table</dt>
        <dd>{c.patternVersion}</dd>
        <dt>Thresholds</dt>
        <dd>{Object.entries(c.thresholds).map(([k, v]) => `${k} ${v}`).join(", ")}</dd>
        <dt>Judge model</dt>
        <dd>{c.judgeModelId ?? "none"}</dd>
      </dl>
    </section>
  );
}

export function Outcome({ d }: { d: SessionDetail }) {
  return (
    <section className={styles.block} aria-labelledby="h-outcome">
      <h2 id="h-outcome">Outcome</h2>
      <dl className={styles.kv}>
        <dt>Secret</dt>
        <dd>
          <Pill tone={d.outcome.obtained ? "bad" : "good"}>{outcomeLabel(d.outcome.obtained)}</Pill>
        </dd>
        <dt>When</dt>
        <dd>{d.outcome.at ? formatTime(d.outcome.at) : "-"}</dd>
        <dt>Echo exclusion</dt>
        <dd>{d.outcome.echoExcluded ? "Excluded (the bot only repeated the student)" : "Not excluded"}</dd>
      </dl>
    </section>
  );
}

export function HeldItems({ d }: { d: SessionDetail }) {
  return (
    <section className={styles.block} aria-labelledby="h-held">
      <h2 id="h-held">Held items</h2>
      {d.heldItems.length === 0 ? (
        <p className="muted">Nothing was held for review.</p>
      ) : (
        <ul className={styles.log}>
          {d.heldItems.map((h) => (
            <li key={h.id}>
              {h.stage}: <Pill tone={h.status === "approved" ? "good" : "bad"}>{h.status.replace("_", " ")}</Pill>
              {h.decidedBy ? <span className="muted"> by {h.decidedBy}</span> : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function Diverts({ d }: { d: SessionDetail }) {
  return (
    <section className={`${styles.block} ${styles.wide}`} aria-labelledby="h-diverts">
      <h2 id="h-diverts">Diverts</h2>
      <p className={styles.sub}>What the student tried, and what they believed they got. No network data is kept here.</p>
      {d.diverts.length === 0 ? (
        <p className="muted">No turns were diverted.</p>
      ) : (
        <ul className={styles.log}>
          {d.diverts.map((v) => (
            <li key={v.id} className={styles.pair}>
              <div>
                <h3>Attempted{v.tool ? ` (${v.tool})` : ""}</h3>
                {v.attemptedSummary}
              </div>
              <div>
                <h3>Student believed</h3>
                {v.decoyShown}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function Forensics({ d }: { d: SessionDetail }) {
  return (
    <section className={styles.block} aria-labelledby="h-forensics">
      <h2 id="h-forensics">Forensic summary</h2>
      {d.forensics ? (
        <dl className={styles.kv}>
          <dt>Attack family</dt>
          <dd>{d.forensics.family}</dd>
          <dt>Summary</dt>
          <dd>{d.forensics.summary}</dd>
        </dl>
      ) : (
        <p className="muted">No forensic report for this session.</p>
      )}
    </section>
  );
}

export function QuizScoreLine({ points }: { points: number | null }) {
  return <>{formatScore(points)}</>;
}
