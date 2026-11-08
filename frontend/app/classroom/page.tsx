import Link from "next/link";

import { Icon, type IconName } from "@/components/shell/Icon";

import { AccessDenied, Unavailable } from "./_components/Common";
import { FilterForm } from "./_components/FilterForm";
import { SessionCards } from "./_components/SessionCards";
import styles from "./_components/classroom.module.css";
import { applyStudentNameFilter, filtersToApiQuery, toSessionList, type ApiSessionList } from "./_lib/adapt";
import { parseFilters } from "./_lib/filters";
import { load } from "./_lib/load";
import { requireViewer } from "./_lib/viewer";

const STUDENT_CARDS: readonly { href: string; title: string; line: string; icon: IconName; tone: string }[] = [
  { href: "/quiz", title: "Quizzes", line: "Explain what happened in your session.", icon: "check", tone: "var(--secondary)" },
  { href: "/arena/sessions", title: "My sessions", line: "What you tried and what stopped you.", icon: "clock", tone: "var(--teal)" },
  { href: "/arena", title: "Practice", line: "Pick a level and try again.", icon: "chat", tone: "var(--accent)" },
];

// Students: three entry cards. Staff: GET /api/classroom/sessions with filters in the URL, validated
// twice (parsed here, unknown values dropped, and by the API with a 422).
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const viewer = await requireViewer();
  if (viewer.kind === "student") {
    return (
      <main>
        <div className="page-head">
          <div>
            <p className="eyebrow learn">Classroom</p>
            <h1>Hi {viewer.name.split(" ")[0]}, what next?</h1>
          </div>
        </div>
        <div className="card-grid">
          {STUDENT_CARDS.map((c) => (
            <Link key={c.href} href={c.href} className="entry-card" style={{ "--tone": c.tone } as React.CSSProperties}>
              <span className="ico">
                <Icon name={c.icon} />
              </span>
              <h2>{c.title}</h2>
              <p>{c.line}</p>
              <span className="go">Open &rarr;</span>
            </Link>
          ))}
        </div>
      </main>
    );
  }
  const filters = parseFilters(await searchParams);
  const query = filtersToApiQuery(filters, viewer.kind);
  const loaded = await load<ApiSessionList>(["classroom", "sessions"], query ? `?${query}` : "");
  const list = loaded.ok ? toSessionList(loaded.data) : null;
  const rows = list ? applyStudentNameFilter(list.rows, filters.student, viewer.kind) : [];
  return (
    <main>
      <div className="page-head">
        <div>
          <p className="eyebrow learn">Classroom</p>
          <h1>Sessions</h1>
          <p className="muted">Open one to see the transcript, decisions and quiz.</p>
        </div>
      </div>
      {!loaded.ok ? (
        loaded.reason === "forbidden" ? (
          <AccessDenied what="the sessions list" home="/" />
        ) : (
          <Unavailable what="sessions" />
        )
      ) : (
        <>
          <FilterForm filters={filters} kind={viewer.kind} levels={list?.levels ?? []} />
          <p className={styles.count} aria-live="polite">
            {rows.length} {rows.length === 1 ? "session" : "sessions"}
          </p>
          <SessionCards rows={rows} />
        </>
      )}
    </main>
  );
}
