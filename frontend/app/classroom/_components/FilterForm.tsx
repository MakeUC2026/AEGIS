import Link from "next/link";

import type { Filters } from "../_lib/filters";
import type { ViewerKind } from "../_lib/types";
import styles from "./classroom.module.css";

const LEVELS = [
  { id: "level-1", name: "Level 1" },
  { id: "level-2", name: "Level 2" },
  { id: "level-3", name: "Level 3" },
];

interface SelectProps {
  name: string;
  label: string;
  value: string | undefined;
  options: readonly { value: string; label: string }[];
}

function Select({ name, label, value, options }: SelectProps) {
  return (
    <label className={styles.field}>
      {label}
      <select name={name} defaultValue={value ?? ""}>
        <option value="">Any</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

const YES_NO = [
  { value: "yes", label: "Yes" },
  { value: "no", label: "No" },
];

// A plain GET form: filter state lives in the URL, so reload and shared links restore it (M4-X07).
export function FilterForm({ filters, kind }: { filters: Filters; kind: ViewerKind }) {
  const staff = kind !== "student";
  return (
    <form method="get" action="/classroom" className={styles.filters} aria-label="Filter sessions">
      {staff ? (
        <label className={styles.field}>
          Student
          <input name="student" defaultValue={filters.student ?? ""} maxLength={64} placeholder="Name contains" />
        </label>
      ) : null}
      <Select name="level" label="Level" value={filters.level} options={LEVELS.map((l) => ({ value: l.id, label: l.name }))} />
      <Select
        name="mode"
        label="Mode"
        value={filters.mode}
        options={[
          { value: "off", label: "Off" },
          { value: "basic", label: "Basic" },
          { value: "strict", label: "Strict" },
        ]}
      />
      <Select
        name="outcome"
        label="Secret"
        value={filters.outcome}
        options={[
          { value: "obtained", label: "Obtained" },
          { value: "not_obtained", label: "Not obtained" },
        ]}
      />
      <Select name="diverted" label="Diverted" value={filters.diverted} options={YES_NO} />
      <Select
        name="quiz_status"
        label="Quiz"
        value={filters.quizStatus}
        options={[
          { value: "not_taken", label: "Not taken" },
          { value: "assigned", label: "Assigned" },
          { value: "in_progress", label: "In progress" },
          { value: "done", label: "Done" },
        ]}
      />
      {staff ? <Select name="admin_test" label="Admin test" value={filters.adminTest} options={YES_NO} /> : null}
      <div className={styles.filterActions}>
        <button type="submit" className="btn-primary">
          Apply
        </button>
        <Link href="/classroom" className="btn-alt">
          Clear
        </Link>
      </div>
    </form>
  );
}
