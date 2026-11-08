import s from "../admin.module.css";
import { patterns } from "../mock";

const CHECKS = [
  ["non_empty", "has conditions"],
  ["matches_source", "matches original call"],
  ["no_benign_match", "matches no benign call"],
] as const;

// A-07 shell. D-01 adds the condition editor and the approve call (all three checks must pass).
export default function Patterns() {
  return (
    <section aria-labelledby="h-patterns">
      <h2 id="h-patterns">Risky patterns</h2>
      <p className={s.note}>Mock data. Only approved patterns affect decisions, in new sessions.</p>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Pattern</th>
              <th>Tool</th>
              <th>Conditions</th>
              <th>Status</th>
              <th>Approval checks</th>
            </tr>
          </thead>
          <tbody>
            {patterns.map((p) => (
              <tr key={p.pattern_id}>
                <td>{p.pattern_id}</td>
                <td>{p.tool}</td>
                <td>
                  {p.conditions.length === 0 ? (
                    <span className="muted">none</span>
                  ) : (
                    p.conditions.map((c) => (
                      <code key={`${c.arg}-${c.op}`} className={s.tag}>
                        {c.arg} {c.op} {JSON.stringify(c.value)}
                      </code>
                    ))
                  )}
                </td>
                <td>
                  {p.status}
                  {p.approved_in_version !== null && ` (v${p.approved_in_version})`}
                </td>
                <td>
                  {CHECKS.map(([key, label]) => (
                    <div key={key} className={p.checks[key] ? s.pass : s.fail}>
                      {p.checks[key] ? "pass" : "fail"}: {label}
                    </div>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
