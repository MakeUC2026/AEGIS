// Arena UI logic (PRD §6.2, §8.5): types mirroring the arena API, the exact player-facing copy,
// the review input lock, message IDs and the browser fingerprint. Pure and unit-tested.

export type TurnStatus = "sent" | "replied" | "blocked" | "awaiting_review" | "human_denied" | "not_sent";

export type ShadowDecision = "allow" | "deny" | "review" | "divert";

export interface FeedItem {
  stage: string;
  decision: "allow" | "deny" | "review" | "human_deny";
  rule_ids: string[];
  score_band: "low" | "medium" | "high";
  shadow_decision?: ShadowDecision | null;
}

export interface ToolEffect {
  call_id: string;
  tool: string;
  state: "executed" | "blocked" | "awaiting_review" | "human_denied";
  visible_content: string | null;
}

export interface Turn {
  message_id: string;
  text: string;
  status: TurnStatus;
  reply: string | null;
  tool_effects: ToolEffect[];
  ticket_id: string | null;
  defense_feed: FeedItem[];
}

export interface TurnResponse extends Turn {
  won: boolean;
  remaining_messages: number | null;
}

export interface ArenaSession {
  id: string;
  level_id: string;
  level_name: string | null;
  mode: "off" | "basic" | "strict";
  status: "active" | "closed";
  won: boolean;
  divert_enabled: boolean | null;
  pending_ticket_id: string | null;
  started_at: string;
  closed_at: string | null;
}

export interface SessionDetail extends ArenaSession {
  turns: Turn[];
  remaining_messages: number;
}

export const PENDING_REVIEW_MESSAGE =
  "Your request is pending human review. The result will appear here once a reviewer decides.";
export const HUMAN_DENIED_MESSAGE = "A reviewer denied this request.";
export const NOT_SENT_MESSAGE = "Firewall unavailable, message not sent";
const SENT_MESSAGE = "Waiting for the assistant…";

export function statusLine(turn: Turn): string {
  switch (turn.status) {
    case "replied":
      return turn.reply ?? "";
    case "blocked": {
      const rules = [...new Set(turn.defense_feed.flatMap((f) => f.rule_ids))];
      return rules.length ? `Blocked. (${rules.join(", ")})` : "Blocked.";
    }
    case "awaiting_review":
      return turn.reply ?? PENDING_REVIEW_MESSAGE;
    case "human_denied":
      return HUMAN_DENIED_MESSAGE;
    case "not_sent":
      return NOT_SENT_MESSAGE;
    default:
      return SENT_MESSAGE;
  }
}

export function inputLocked(turns: readonly Turn[]): boolean {
  return turns.some((t) => t.status === "awaiting_review");
}

export function newMessageId(): string {
  return `m${Date.now().toString(36)}${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
}

export interface FingerprintParts {
  userAgent: string;
  language: string;
  timezone: string;
  screen: string;
  platform: string;
}

/** SHA-256 of user agent, accept-language, timezone, screen size and platform (PRD §8.5). */
export async function computeFingerprint(parts: FingerprintParts): Promise<string> {
  const data = new TextEncoder().encode(
    [parts.userAgent, parts.language, parts.timezone, parts.screen, parts.platform].join("|"),
  );
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function browserFingerprintParts(): FingerprintParts {
  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: `${window.screen.width}x${window.screen.height}`,
    platform: navigator.platform,
  };
}

const SHADOW_VERBS: Record<ShadowDecision, string> = {
  allow: "allowed",
  deny: "denied",
  review: "sent to review",
  divert: "diverted",
};

/** Off-mode feed line for what the firewall would have done (PRD D-02). */
export function shadowLabel(decision: ShadowDecision): string {
  return `would have ${SHADOW_VERBS[decision]}`;
}
