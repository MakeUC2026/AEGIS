// View-model types for the Classroom screens. In Phase B these are filled from the API; for now
// from mock data. Shapes mirror the C3/C4 contracts (backend/app/contracts) without network data.

export type Mode = "off" | "basic" | "strict";
export type QuizStatus = "not_taken" | "assigned" | "in_progress" | "done";
export type ViewerKind = "student" | "teacher" | "firewall_admin";

export interface SessionRow {
  id: string;
  studentId: string;
  studentName: string;
  levelId: string;
  levelName: string;
  mode: Mode;
  status: "active" | "closed";
  secretObtained: boolean;
  divertedCount: number;
  maxSentinelScore: number | null;
  startedAt: string;
  quizStatus: QuizStatus;
  quizPoints: number | null; // out of 17, latest attempt
  quizId: string | null;
  adminTest: boolean;
}

export interface TranscriptLine {
  id: string;
  time: string;
  speaker: "student" | "bot" | "tool";
  text: string; // untrusted: always rendered as escaped text
  status: "replied" | "blocked" | "awaiting_review" | "human_denied" | null;
  isDecoy: boolean;
}

export interface DecisionLine {
  id: string;
  stage: string;
  decision: "allow" | "deny" | "review" | "human_deny" | "divert";
  score: number;
  breakdown: Record<string, number | null>; // null: the layer did not run
  rules: string[];
  riskyPatterns: string[];
}

export interface SessionDetail {
  row: SessionRow;
  transcript: TranscriptLine[];
  decisions: DecisionLine[];
  config: {
    levelVersion: number;
    mode: Mode;
    ruleVersion: number;
    patternVersion: number;
    thresholds: Record<string, number>;
    judgeModelId: string | null;
  };
  outcome: { obtained: boolean; at: string | null; echoExcluded: boolean };
  heldItems: {
    id: string;
    stage: string;
    status: "pending" | "approved" | "human_denied" | "expired";
    decidedBy: string | null;
  }[];
  diverts: { id: string; stage: string; tool: string | null; attemptedSummary: string; decoyShown: string }[];
  forensics: { family: string; summary: string } | null;
}
