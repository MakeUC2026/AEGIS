// Shapes of the /api/admin responses (backend/app/contracts/firewall_admin.py, arena.py,
// firewall_read.py and backend/app/admin/decisions.py). Keep in step with the contracts.

export type Mode = "off" | "basic" | "strict";
export type Decision = "allow" | "deny" | "review" | "human_deny" | "divert";
export type Stage = "input_check" | "tool_call_check" | "tool_executed" | "reply_check" | string;

export interface EventRow {
  event_id: string;
  time: string;
  fw_session_id: string;
  user_id: string;
  mode: Mode;
  stage: Stage;
  decision: Decision;
  shadow_decision: Decision | null;
  sentinel_score: number;
  rule_ids: string[];
  judge_risk: number | null;
  judge_reason: string | null;
  forensic_status: string | null;
}

export interface Ticket {
  ticket_id: string;
  fw_session_id: string;
  user_id: string;
  stage: Stage;
  student_command: string;
  held_tool: string | null;
  held_args: Record<string, unknown> | null;
  held_reply: string | null;
  sentinel_score: number;
  score_breakdown: Record<string, number | null>;
  rule_ids: string[];
  expires_at: string;
  priority_alert: boolean;
}

export const APPLIES_ON = ["player_message", "tool_result", "bot_tool_call", "bot_reply", "session_history"] as const;
export const CHECKS = ["text", "tool_name", "named_argument", "turn_count", "earlier_denies"] as const;
export const RULE_ACTIONS = ["score_only", "allow", "review", "deny", "divert"] as const;
export const ATLAS_TAGS = ["AML.T0051.000", "AML.T0051.001", "AML.T0053", "AML.T0086"] as const;
const TEXT_OPS = ["contains", "equals", "regex", "in_list"];
export const OPERATORS_BY_CHECK: Record<(typeof CHECKS)[number], string[]> = {
  text: TEXT_OPS,
  tool_name: ["equals", "in_list"],
  named_argument: [...TEXT_OPS, "domain_in", "domain_not_in", "inside_workspace", "outside_workspace"],
  turn_count: ["equals", "greater_than", "less_than"],
  earlier_denies: ["equals", "greater_than", "less_than"],
};

export interface RuleForm {
  applies_on: (typeof APPLIES_ON)[number];
  checks: (typeof CHECKS)[number];
  argument_name: string | null;
  operator: string;
  value: string | number | string[];
  action: (typeof RULE_ACTIONS)[number];
  weight: number | null;
  atlas_tag: (typeof ATLAS_TAGS)[number] | null;
  note: string;
}

export interface RuleDef {
  rule_id: string;
  version: number;
  builtin: boolean;
  enabled: boolean;
  deprecated: boolean;
  form: RuleForm | null;
  created_at: string;
  created_by: string | null;
}

export interface LevelSummary {
  level_id: string;
  level_version: number;
  number: number;
  name: string;
  mode: Mode;
  secret_tier: string;
  rule_version: number;
  weights: Record<string, number>;
  thresholds: Record<string, number>;
  review_timeout_s: number;
  divert_enabled: boolean;
  created_at: string;
}

export interface Draft {
  draft_id: string;
  source_event_id: string | null;
  kind: string;
  body: Record<string, unknown>;
  status: string;
  validation: { ok?: boolean; reasons?: string[] } | null;
  cluster_size: number;
  result_ref: string | null;
  created_at: string;
  needs_reconcile?: boolean;
}

export interface Pattern {
  pattern_id: string;
  tool: string;
  conditions: { arg: string; op: string; value: unknown }[];
  status: "candidate" | "approved" | "rejected" | "retired";
  approved_in_version: number | null;
  retired_in_version: number | null;
  source_event_id: string | null;
  source_args: Record<string, unknown> | null;
  source_draft_id: string | null;
  created_at: string;
}

export interface TraceBack {
  trace_id: string;
  time: string;
  ip_hash: string | null;
  subnet: string | null;
  asn: number | null;
  asn_org: string | null;
  country: string | null;
  user_agent: string | null;
  client_fingerprint: string | null;
  methods_used: string[];
  tools_called: string[];
}

export interface DivertAdminItem {
  divert: { event_id: string; time: string; stage: Stage; tool: string | null; attempted_summary: string; decoy_shown: string };
  fw_session_id: string;
  user_id: string;
  trace_back: TraceBack | null;
}

export interface ForensicRow {
  event_id: string;
  mode: Mode;
  stage: Stage;
  decision: Decision;
  status: string;
  attack_family: string | null;
  atlas_techniques: string[] | null;
  summary: string | null;
  missed_signals: unknown;
  would_have_blocked_in: unknown;
  failure_reason: string | null;
  created_at: string;
}

export interface AuditRow {
  id: number;
  time: string;
  actor_id: string | null;
  entity: string;
  entity_id: string;
  action: string;
  before: unknown;
  after: unknown;
}
