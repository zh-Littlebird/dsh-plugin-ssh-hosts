/**
 * Command risk classification for human approval. This is a guardrail, not a
 * shell sandbox: an obfuscated command can evade pattern matching, which is why
 * the server allowlist, path allowlist, and audit log exist independently.
 */
export interface RiskAssessment {
    high: boolean;
    reasons: string[];
    matched: string[];
}
/** Classify one command; the reasons are safe to show to the user. */
export declare function assessCommandRisk(command: string): RiskAssessment;
/** One-line human summary used in approval prompts and audit lines. */
export declare function describeRisk(assessment: RiskAssessment): string;
