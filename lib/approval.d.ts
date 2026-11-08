/** Human approval for commands classified as high risk. */
import type { ToolRunContext } from '@deepseek-ai/dsh-tools';
import type { ToolDeps } from './deps.js';
import type { RiskAssessment } from './risk.js';
import type { HostRecord } from './types.js';
export type ApprovalState = 'not-required' | 'granted' | 'policy-allow' | 'full-access';
/**
 * Apply the configured high-risk policy.
 *
 * Order of precedence:
 * 1. `highRiskPolicy` — an explicit deployment decision (`allow`/`deny`).
 * 2. Session permission preset — under “完全权限” (approval `never` plus
 *    `danger-full-access`) prompts cannot be shown, and the user has already
 *    accepted that risk, so risky commands are allowed and marked
 *    `full-access`. A `never` policy over a restricted sandbox still fails
 *    closed with an explanatory error.
 * 3. Interactive `ask` — always fails closed when the answerer is missing,
 *    the caller has no agent, or the user does not grant.
 */
export declare function requireApproval(deps: ToolDeps, exec: ToolRunContext, host: HostRecord, command: string, risk: RiskAssessment): Promise<ApprovalState>;
