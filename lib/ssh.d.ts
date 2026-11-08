/**
 * SSH transport: pooled connections, host-key trust, command execution with
 * bounded output and timeouts, and SFTP file operations constrained by the
 * server's path policy.
 */
import type { SshHostsConfig } from './config.js';
import type { DebugLogger } from './redact.js';
import type { ExecResult, HostRecord, SudoMode, TestResult } from './types.js';
import { type RemotePathPolicy } from './paths.js';
export interface ResolvedCredentials {
    password?: string;
    privateKey?: Buffer;
    passphrase?: string;
}
export type CredentialResolver = (host: HostRecord) => Promise<ResolvedCredentials>;
export interface SshManagerOptions {
    config: SshHostsConfig;
    credentials: CredentialResolver;
    onFingerprint: (host: HostRecord, fingerprint: string) => Promise<void>;
    debug: DebugLogger;
}
interface ExecOptions {
    cwd?: string;
    timeoutMs?: number;
    maxOutputBytes?: number;
    signal?: AbortSignal;
    /** Run the command through the host's configured sudo. */
    privilege?: ExecPrivilege;
}
/** Resolved privilege escalation for one command. */
export interface ExecPrivilege {
    mode: SudoMode;
    /** Target account; `root` when omitted. */
    user?: string;
    /** Password for `mode: 'password'`; written to stdin, never logged. */
    password?: string;
}
interface WriteOptions {
    createDirs?: boolean;
    overwrite?: boolean;
}
/** OpenSSH-style SHA256 fingerprint over the raw host key blob. */
export declare function hostKeyFingerprint(key: Buffer): string;
/**
 * Wrap one command so it runs under the host's configured sudo.
 *
 * The `cd` stays outside `sudo` so the working directory is resolved by the
 * login user and inherited by the privileged shell (sudo never changes cwd).
 * `-S` reads the password from stdin, `-k` forces a fresh authentication so a
 * cached timestamp can never swallow the password line meant for sudo, `-H`
 * points `$HOME` at the target account, and `-p ""` hides the prompt text.
 * `-n` (nopasswd mode) fails immediately instead of waiting for input.
 */
export declare function wrapPrivilegedCommand(command: string, cwd: string, privilege: ExecPrivilege): string;
/** The connection pool and all remote operations, owned by one plugin context. */
export declare class SshManager {
    private readonly options;
    private readonly pool;
    private readonly pending;
    private readonly semaphores;
    private disposed;
    constructor(options: SshManagerOptions);
    /** Close every pooled connection and stop idle timers. */
    dispose(): Promise<void>;
    /** Connect, authenticate, learn the home directory, and report trust status. */
    test(host: HostRecord): Promise<TestResult>;
    /** Execute one command on the server; a non-zero exit is a normal result. */
    exec(host: HostRecord, command: string, options?: ExecOptions): Promise<ExecResult>;
    /** Read a remote text file, refusing binary content and capping bytes. */
    readFile(host: HostRecord, input: string, maxBytes: number): Promise<{
        content: string;
        bytes: number;
        originalBytes: number;
        truncated: boolean;
        path: string;
    }>;
    /** Create or replace a remote text file after permission and path checks. */
    writeFile(host: HostRecord, input: string, content: string, options?: WriteOptions): Promise<{
        path: string;
        bytesWritten: number;
        created: boolean;
        overwritten: boolean;
    }>;
    /** Stream one local file to the server. */
    upload(host: HostRecord, localPath: string, remoteInput: string, options?: WriteOptions): Promise<{
        remotePath: string;
        bytes: number;
        overwritten: boolean;
    }>;
    /** Stream one remote file to a local path through a temporary sibling. */
    download(host: HostRecord, remoteInput: string, localPath: string, options?: WriteOptions): Promise<{
        remotePath: string;
        bytes: number;
        overwritten: boolean;
    }>;
    /**
     * Build the effective path policy for one host and optional cwd.
     *
     * The plugin-level `tempDir` (default `/tmp`) is folded into both lists so
     * the model has one predictable scratch place on every server instead of
     * writing process files into service directories. `deniedPaths` still wins,
     * and a disabled `tempDir` restores the per-host policy exactly.
     */
    policyFor(host: HostRecord, home: string, cwd?: string): RemotePathPolicy;
    private withEntry;
    private semaphoreFor;
    private connectionKey;
    private getEntry;
    private open;
    /** Resolve `$HOME` over an exec channel when the SFTP subsystem is absent. */
    private homeViaExec;
    private getSftp;
    private verifyRealPath;
    /** Verify the deepest existing ancestor before creating directories under it. */
    private verifyExistingAncestor;
    private mkdirp;
    private scheduleIdle;
    private drop;
    private closeEntry;
}
export {};
