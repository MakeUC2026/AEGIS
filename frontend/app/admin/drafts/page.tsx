import s from "../admin.module.css";
import { drafts } from "../mock";

// A-07 shell. Failed drafts are listed but can never be approved (PRD §10.3, E-56).
export default function Drafts() {
  return (
    <section aria-labelledby="h-drafts">
      <h2 id="h-drafts">Drafts</h2>
      <p className={s.note}>Mock data. Drafts are never applied without an admin approval.</p>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Draft</th>
              <th>Kind</th>
              <th>Source event</th>
              <th>Family</th>
              <th>Summary</th>
              <th>Validation</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {drafts.map((d) => {
              const failed = d.status === "failed_validation";
              return (
                <tr key={d.draft_id}>
                  <td>
                    {d.draft_id}
                    {d.cluster_count > 1 && <span className={s.tag}>x{d.cluster_count}</span>}
                  </td>
                  <td>{d.kind}</td>
                  <td>{d.source_event_id}</td>
                  <td>{d.attack_family}</td>
                  <td>{d.summary}</td>
                  <td className={failed ? s.fail : s.pass}>
                    {failed ? d.validation.join("; ") : "passed"}
                  </td>
                  <td className={s.actions}>
                    <button type="button" className="button" disabled>
                      approve
                    </button>
                    <button type="button" className="button" disabled>
                      edit
                    </button>
                    <button type="button" className="button" disabled>
                      reject
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
