import { redirect } from "next/navigation";

import { type LevelCard, LevelPicker } from "@/components/arena/LevelPicker";
import { getMe, serverGet } from "@/lib/server-api";

interface LevelsView {
  levels: LevelCard[];
  rules: { rule_id: string; applies_on: string; action: string; note: string }[];
  remaining_messages: number;
}

// Start screen (PRD §6.1): level cards, rule catalog, remaining messages.
export default async function ArenaPage() {
  if (!(await getMe())) redirect("/");
  const view = await serverGet<LevelsView>(["arena", "levels"]);
  return (
    <main>
      <h1>Arena</h1>
      <p className="muted">
        Pick a level and talk the assistant into revealing its secret. {view.remaining_messages} messages left this hour.
      </p>
      <LevelPicker levels={view.levels} />
      <section className="panel rules" aria-label="Rules the firewall runs">
        <h2>Rules the firewall runs</h2>
        <p className="muted">Off computes these in shadow only; Basic and Strict enforce them.</p>
        <ul>
          {view.rules.map((r) => (
            <li key={r.rule_id}>
              <strong>{r.rule_id}</strong> · {r.note} <span className="muted">({r.applies_on.replaceAll("_", " ")}, {r.action})</span>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
