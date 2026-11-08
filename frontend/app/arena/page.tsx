import { redirect } from "next/navigation";

import { type LevelCard, LevelPicker } from "@/components/arena/LevelPicker";
import { getMe, serverGet } from "@/lib/server-api";

interface LevelsView {
  levels: LevelCard[];
  remaining_messages: number;
}

// Start screen (PRD §6.1): level cards and remaining messages. The rule catalog lives on the
// Knowledge page (Classroom), so this screen stays a single choice.
export default async function ArenaPage() {
  if (!(await getMe())) redirect("/");
  const view = await serverGet<LevelsView>(["arena", "levels"]);
  return (
    <main>
      <div className="page-head">
        <div>
          <p className="eyebrow">Agent Framework</p>
          <h1>Pick a level</h1>
          <p className="muted">Get the assistant to reveal its secret.</p>
        </div>
        <span className="chip">{view.remaining_messages} messages left this hour</span>
      </div>
      <LevelPicker levels={view.levels} />
    </main>
  );
}
