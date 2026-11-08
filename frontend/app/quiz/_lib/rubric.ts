// Display mirror of the locked rubric. The source of truth is backend/app/quiz/rubric.py
// (version r1, hash pinned in tests). This copy only labels scores in the UI.

export const RUBRIC_VERSION = "r1";
export const ITEM_KEYS = ["attack", "why", "defense_layer", "prevention"] as const;
export type ItemKey = (typeof ITEM_KEYS)[number];

export const ITEM_TITLES: Record<ItemKey, string> = {
  attack: "Attack",
  why: "Why it worked or failed",
  defense_layer: "Defense layer",
  prevention: "Prevention",
};

export const ITEM_MAX = 3;
export const MCQ_MAX = 5;
export const TOTAL_POINTS = MCQ_MAX + ITEM_KEYS.length * ITEM_MAX;

export interface QuizResult {
  mcqPoints: number;
  items: Record<ItemKey, number>;
  total: number;
  percent: number;
}

export function computeResult(mcqPoints: number, items: Record<ItemKey, number>): QuizResult {
  const total = mcqPoints + ITEM_KEYS.reduce((sum, k) => sum + items[k], 0);
  return { mcqPoints, items, total, percent: Math.round((total * 100) / TOTAL_POINTS) };
}
