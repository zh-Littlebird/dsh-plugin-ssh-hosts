/** Shared dependency surface passed to every tool factory. */
import type { ToolRunContext } from '@deepseek-ai/dsh-tools';
import type { AuditLog } from './audit.js';
import type { SshHostsConfig } from './config.js';
import type { HostStore } from './hosts.js';
import type { DebugLogger } from './redact.js';
import type { SecretStore } from './secrets.js';
import type { SshManager } from './ssh.js';
export type ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable';
export interface ApprovalRequest {
    agent: {
        readonly id: string;
    };
    toolName: string;
    callId?: string;
    reason?: string;
    displayReason?: {
        readonly en: string;
        readonly [locale: string]: string;
    };
    signal?: AbortSignal;
}
export interface ApprovalService {
    request(request: ApprovalRequest): Promise<ApprovalOutcome>;
    /**
     * Present on the real Harness approval service: the session's effective
     * policy (`ask` or `never`), folding a `/permission` override over the
     * deployment default. Optional so tests and older hosts keep working.
     */
    effectivePolicy?(session: unknown): string | undefined;
}
/**
 * The permission preset a session runs under.
 *
 * DSH exposes the same facts through two seams: the approval service owns
 * `ask`/`never`, and the sandbox-policy service owns
 * `read-only`/`workspace-write`/`danger-full-access`. The Web GUI's “完全权限”
 * preset sets both to the permissive values.
 */
export type ApprovalPolicy = 'ask' | 'never' | 'unknown';
export type SandboxMode = 'read-only' | 'workspace-write' | 'danger-full-access' | 'unknown';
export interface SessionTrust {
    approvalPolicy: ApprovalPolicy;
    sandboxMode: SandboxMode;
    /** True when the approval service answers `never`: no prompt can be shown. */
    promptsDisabled: boolean;
    /** True when prompts are disabled and the file sandbox does not restrict writes. */
    fullAccess: boolean;
}
/** Read the current session's permission preset for one tool call. */
export type TrustResolver = (exec: ToolRunContext) => SessionTrust;
export interface ToolDeps {
    config: SshHostsConfig;
    dataDir: string;
    store: HostStore;
    secrets: SecretStore;
    manager: SshManager;
    audit: AuditLog;
    approval: ApprovalService | undefined;
    trust: TrustResolver;
    debug: DebugLogger;
}
