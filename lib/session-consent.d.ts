/**
 * Per-server consent for the SSH plugin.
 *
 * DSH's approval seam is deliberately one-shot: every call to
 * `approval.request()` needs a fresh human decision. Asking before every
 * `ssh_*` call would make the plugin unusable, so this gate remembers a
 * positive answer for the rest of the session — but only for the exact target
 * the user approved. The target is one configured server (keyed by its stable
 * host id, not its alias), plus one separate scope for the local host
 * inventory (`ssh_host_list` / `ssh_host_add`). Approving server A never
 * approves server B, and a new session starts with no grants at all.
 *
 * Grants live only in this process: a Harness restart asks again. A denial is
 * never remembered, so a user who changes their mind can approve a later call
 * without opening a new session.
 *
 * A session whose approval policy is `never` (the GUI's “完全权限”) can never
 * show a prompt. With `trustFullAccess` enabled the gate records the grant
 * without asking; that is the only way the plugin can work in that preset.
 */
import type { ToolRunContext } from '@deepseek-ai/dsh-tools';
import type { SshHostsConfig } from './config.js';
import type { ApprovalService, TrustResolver } from './deps.js';
import type { DebugLogger } from './redact.js';
/** Resolve an alias or id to the stable host identity a grant is keyed by. */
export type ServerResolver = (server: string) => Promise<{
    id: string;
    alias: string;
    host: string;
    username: string;
} | undefined>;
/**
 * Ask the user once per session and per target, before the tool body runs.
 * Concurrent first calls for the same target share one in-flight request, so a
 * model that issues a parallel batch cannot produce several prompts for the
 * same server.
 */
export declare class SessionConsentGate {
    private readonly config;
    private readonly approval;
    private readonly debug;
    private readonly resolveServer;
    private readonly trust;
    private readonly granted;
    private readonly pending;
    constructor(config: SshHostsConfig, approval: ApprovalService | undefined, debug: DebugLogger, resolveServer: ServerResolver, trust: TrustResolver);
    /** Throw unless this session may use the target of this call right now. */
    ensure(exec: ToolRunContext, toolName: string, args: unknown): Promise<void>;
    /** Drop every in-memory grant; used when the plugin is disposed. */
    dispose(): void;
    private targetOf;
    private requestConsent;
}
