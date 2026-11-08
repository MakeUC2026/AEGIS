"use client";

import { useState } from "react";

import { apiFetch } from "@/lib/api";

import { APPLIES_ON, ATLAS_TAGS, CHECKS, OPERATORS_BY_CHECK, RULE_ACTIONS, type RuleDef, type RuleForm } from "../_ui/types";
import { Chip, ConsoleTabs, PageHead, Segments, State, act, useApi, words } from "../_ui/ui";
import s from "../_ui/console.module.css";

const BLANK: RuleForm = { applies_on: "player_message", checks: "text", argument_name: null, operator: "contains", value: "", action: "score_only", weight: 20, atlas_tag: null, note: "" };
const NUMERIC = new Set(["turn_count", "earlier_denies"]);

function Editor({ rule, onDone }: { rule: RuleDef | null; onDone: () => void }) {
  const [f, setF] = useState<RuleForm>(rule?.form ?? BLANK);
  const [error, setError] = useState<string | null>(null);
  const ops = OPERATORS_BY_CHECK[f.checks];
  const set = (patch: Partial<RuleForm>) => setF({ ...f, ...patch });
  const valueText = Array.isArray(f.value) ? f.value.join(", ") : String(f.value);

  async function save() {
    const value = NUMERIC.has(f.checks) ? Number(valueText) : f.operator === "in_list" || f.operator.startsWith("domain_") ? valueText.split(",").map((v) => v.trim()).filter(Boolean) : valueText;
    const json = { ...f, value, argument_name: f.checks === "named_argument" ? f.argument_name : null, weight: f.action === "score_only" ? f.weight : null };
    const path = rule ? `admin/rules/${rule.rule_id}` : "admin/rules";
    setError(await act(() => apiFetch(path, { method: rule ? "PUT" : "POST", json }), onDone));
  }

  return (
    <section className="panel" aria-label={rule ? `Edit ${rule.rule_id}` : "New rule"} style={{ marginBottom: 16 }}>
      <div className={s.panelHead}>
        <h2>{rule ? `Edit ${rule.rule_id}` : "New rule"}</h2>
      </div>
      <div className={s.form}>
        <label>
          Applies on
          <select value={f.applies_on} onChange={(e) => set({ applies_on: e.target.value as RuleForm["applies_on"] })}>
            {APPLIES_ON.map((v) => (
              <option key={v} value={v}>
                {words(v)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Checks
          <select value={f.checks} onChange={(e) => {
            const checks = e.target.value as RuleForm["checks"];
            set({ checks, operator: OPERATORS_BY_CHECK[checks][0] });
          }}>
            {CHECKS.map((v) => (
              <option key={v} value={v}>
                {words(v)}
              </option>
            ))}
          </select>
        </label>
        {f.checks === "named_argument" ? (
          <label>
            Argument
            <input value={f.argument_name ?? ""} onChange={(e) => set({ argument_name: e.target.value })} placeholder="path" />
          </label>
        ) : null}
        <label>
          Operator
          <select value={f.operator} onChange={(e) => set({ operator: e.target.value })}>
            {ops.map((v) => (
              <option key={v} value={v}>
                {words(v)}
              </option>
            ))}
          </select>
        </label>
        <label className="full">
          Value {f.operator === "in_list" || f.operator.startsWith("domain_") ? "(comma separated)" : ""}
          <input value={valueText} onChange={(e) => set({ value: e.target.value })} />
        </label>
        <label>
          Action
          <select value={f.action} onChange={(e) => set({ action: e.target.value as RuleForm["action"] })}>
            {RULE_ACTIONS.map((v) => (
              <option key={v} value={v}>
                {words(v)}
              </option>
            ))}
          </select>
        </label>
        {f.action === "score_only" ? (
          <label>
            Weight (5–60)
            <input type="number" min={5} max={60} value={f.weight ?? 20} onChange={(e) => set({ weight: Number(e.target.value) })} />
          </label>
        ) : null}
        <label>
          ATLAS tag
          <select value={f.atlas_tag ?? ""} onChange={(e) => set({ atlas_tag: (e.target.value || null) as RuleForm["atlas_tag"] })}>
            <option value="">none</option>
            {ATLAS_TAGS.map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </label>
        <label className="full">
          Note
          <input value={f.note} onChange={(e) => set({ note: e.target.value })} placeholder="What this rule catches" />
        </label>
        <div className={`full ${s.actions}`}>
          <button className="btn-primary" type="button" onClick={save}>
            {rule ? "Save version" : "Add rule"}
          </button>
          <button className="btn-alt" type="button" onClick={onDone}>
            Cancel
          </button>
          {error ? (
            <p className={s.err} role="alert">
              {error}
            </p>
          ) : null}
        </div>
      </div>
    </section>
  );
}

const VIEWS = ["active", "deleted"] as const;

// Rules (PRD §9.1): versioned. "Delete" deprecates (kept with its history) and can be restored.
export default function Rules() {
  const api = useApi<RuleDef[]>("admin/rules");
  const [view, setView] = useState<(typeof VIEWS)[number]>("active");
  const [editing, setEditing] = useState<RuleDef | "new" | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const done = () => {
    setEditing(null);
    api.reload();
  };
  const run = async (path: string, json?: unknown) => {
    setConfirming(null);
    setError(await act(() => apiFetch(path, { method: "POST", json }), api.reload));
  };
  return (
    <main className="wide">
      <PageHead title="Firewall console" line="Versioned rules. Deleted rules are kept and can be restored.">
        <button className="btn-primary" type="button" onClick={() => setEditing("new")}>
          Add rule
        </button>
      </PageHead>
      <ConsoleTabs />
      {editing ? <Editor key={editing === "new" ? "new" : editing.rule_id} rule={editing === "new" ? null : editing} onDone={done} /> : null}
      {error ? (
        <p className={s.err} role="alert">
          {error}
        </p>
      ) : null}
      <Segments label="Rule list" value={view} options={VIEWS} onChange={setView} />
      <State api={api} empty="No rules returned.">
        {(all) => {
          const rows = all.filter((r) => r.deprecated === (view === "deleted"));
          if (rows.length === 0) return <p className="panel muted">{view === "deleted" ? "No deleted rules." : "No active rules."}</p>;
          return (
          <div className={`panel ${s.tableWrap}`} style={{ padding: 0 }}>
            <table className={s.table}>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>What it catches</th>
                  <th>Action</th>
                  <th>State</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.rule_id}>
                    <td className="mono">
                      {r.rule_id} <small className="muted">v{r.version}</small>
                    </td>
                    <td>
                      {r.form?.note ?? <span className="muted">{r.builtin ? "built-in check" : "starting rule"}</span>}
                      {r.form ? <div className="muted">{words(r.form.applies_on)}</div> : null}
                    </td>
                    <td>{r.form ? <Chip value={r.form.action} /> : <span className="chip">{r.builtin ? "built-in" : "seeded"}</span>}</td>
                    <td>{r.deprecated ? <span className="chip">deleted</span> : <Chip value={r.enabled ? "enabled" : "disabled"} />}</td>
                    <td>
                      <div className={s.actions}>
                        {r.deprecated ? (
                          <button className="btn-alt" type="button" onClick={() => run(`admin/rules/${r.rule_id}/restore`)}>
                            Restore
                          </button>
                        ) : confirming === r.rule_id ? (
                          <>
                            <button className="btn-alt" type="button" style={{ borderColor: "var(--danger)", color: "var(--danger)" }} onClick={() => run(`admin/rules/${r.rule_id}/deprecate`)}>
                              Confirm delete
                            </button>
                            <button className="btn-alt" type="button" onClick={() => setConfirming(null)}>
                              Cancel
                            </button>
                          </>
                        ) : (
                          <>
                            {r.form ? (
                              <button className="btn-alt" type="button" onClick={() => setEditing(r)}>
                                Edit
                              </button>
                            ) : null}
                            <button className="btn-alt" type="button" onClick={() => run(`admin/rules/${r.rule_id}/enabled`, { enabled: !r.enabled })}>
                              {r.enabled ? "Disable" : "Enable"}
                            </button>
                            {r.builtin ? null : (
                              <button className="btn-alt" type="button" onClick={() => setConfirming(r.rule_id)}>
                                Delete
                              </button>
                            )}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          );
        }}
      </State>
    </main>
  );
}
