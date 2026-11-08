/** Deployment configuration, defaults, and the resolved data directory. */
import z from '@deepseek-ai/schemastery';
import type { SecretsBackend } from './types.js';
export type HighRiskPolicy = 'ask' | 'deny' | 'allow';
/**
 * How the first `ssh_*` call for a target is admitted.
 *
 * `ask` (the default) asks the user through the approval seam exactly once per
 * session and per target (one server, or one inventory scope), then remembers
 * the grant in this process. `allow` restores the old unconditional behaviour,
 * and `deny` blocks every tool call. A process restart clears the in-memory
 * grants, so a resumed session is asked again.
 */
export type SessionConsentPolicy = 'ask' | 'allow' | 'deny';
export interface SshHostsConfig {
    /** Directory for hosts.json, credentials, known keys, transfers, and audit.log. */
    dataDir: string;
    /** Per-stream output cap before head/tail truncation. */
    maxOutputBytes: number;
    /** Default command timeout. */
    timeoutMs: number;
    /** Upper bound a model may request per call. */
    maxTimeoutMs: number;
    /** TCP/SSH handshake timeout. */
    connectTimeoutMs: number;
    /** Close an unused connection after this period. */
    idleTimeoutMs: number;
    /** Concurrent operations allowed on one server. */
    maxConcurrentPerHost: number;
    /** Largest file read, upload, or download. */
    maxTransferBytes: number;
    /** Where passwords and key passphrases come from. */
    secretsBackend: SecretsBackend;
    /** Prefix for environment-backed secrets. */
    envPrefix: string;
    /** What to do with a command classified as high risk. */
    highRiskPolicy: HighRiskPolicy;
    /** Whether the first `ssh_*` call for a server (or inventory scope) asks the user. */
    sessionConsent: SessionConsentPolicy;
    /**
     * Trust a session whose approval prompts are disabled (“完全权限”):
     * treat the SSH authorization and high-risk commands as already granted
     * instead of failing closed on a prompt that can never be shown.
     */
    trustFullAccess: boolean;
    /** Append one JSON line per operation. */
    audit: boolean;
    /** Verbose, redacted diagnostics on stderr. */
    debug: boolean;
    /** Extra local roots that upload/download may read or write. */
    localRoots: string[];
    /** Refuse absolute path arguments in commands that leave the allowed roots. */
    strictCommandPaths: boolean;
    /** Refuse edit-like shell commands outside editablePaths. */
    guardCommandEdits: boolean;
    /**
     * Remote scratch directory granted read+write on every host (default `/tmp`).
     * It is folded into the effective `allowedPaths`/`editablePaths`, so the
     * model can keep process files there instead of scattering them across
     * service directories. An empty string disables the grant.
     */
    tempDir: string;
}
export declare const Config: z<Schemastery.ObjectS<NoInfer<{
    dataDir: z<string, string, "defined">;
    maxOutputBytes: z<number, number, "defined">;
    timeoutMs: z<number, number, "defined">;
    maxTimeoutMs: z<number, number, "defined">;
    connectTimeoutMs: z<number, number, "defined">;
    idleTimeoutMs: z<number, number, "defined">;
    maxConcurrentPerHost: z<number, number, "defined">;
    maxTransferBytes: z<number, number, "defined">;
    secretsBackend: z<string, string, "defined">;
    envPrefix: z<string, string, "defined">;
    highRiskPolicy: z<string, string, "defined">;
    sessionConsent: z<string, string, "defined">;
    trustFullAccess: z<boolean, boolean, "defined">;
    audit: z<boolean, boolean, "defined">;
    debug: z<boolean, boolean, "defined">;
    localRoots: z<string[], string[], "defined">;
    strictCommandPaths: z<boolean, boolean, "defined">;
    guardCommandEdits: z<boolean, boolean, "defined">;
    tempDir: z<string, string, "defined">;
}>>, Schemastery.ObjectT<NoInfer<{
    dataDir: z<string, string, "defined">;
    maxOutputBytes: z<number, number, "defined">;
    timeoutMs: z<number, number, "defined">;
    maxTimeoutMs: z<number, number, "defined">;
    connectTimeoutMs: z<number, number, "defined">;
    idleTimeoutMs: z<number, number, "defined">;
    maxConcurrentPerHost: z<number, number, "defined">;
    maxTransferBytes: z<number, number, "defined">;
    secretsBackend: z<string, string, "defined">;
    envPrefix: z<string, string, "defined">;
    highRiskPolicy: z<string, string, "defined">;
    sessionConsent: z<string, string, "defined">;
    trustFullAccess: z<boolean, boolean, "defined">;
    audit: z<boolean, boolean, "defined">;
    debug: z<boolean, boolean, "defined">;
    localRoots: z<string[], string[], "defined">;
    strictCommandPaths: z<boolean, boolean, "defined">;
    guardCommandEdits: z<boolean, boolean, "defined">;
    tempDir: z<string, string, "defined">;
}>>, "plain">;
/** Fill omissions so `apply` behaves the same when called without the Loader. */
export declare function withDefaults(config: Partial<SshHostsConfig> | undefined): SshHostsConfig;
/** `$DSH_HOME/ssh-hosts`, or the same path under the user's home when unset. */
export declare function resolveDataDir(config: SshHostsConfig): string;
/**
 * The configured scratch directory as shown to humans and the model, or null
 * when the grant is disabled. `~/…` stays literal here because the login home
 * is only known after connecting; {@link resolveTempRoot} expands it for the
 * actual path checks.
 */
export declare function configuredTempDir(config: SshHostsConfig): string | null;
