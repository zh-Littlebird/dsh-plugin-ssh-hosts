/** Durable host inventory: validation, atomic persistence, and redacted views. */
import type { AuthType, FingerprintPolicy, HostRecord, HostService, HostSudo, HostView, SudoMode } from './types.js';
export declare const HOSTS_FILE = "hosts.json";
export declare const DEFAULT_DENIED_PATHS: string[];
/** What a user or the management page may say about one host's sudo policy. */
export interface SudoInput {
    /** `off` clears the policy; the password itself is never part of this shape. */
    mode: 'off' | SudoMode;
    /** Target account; `null`/empty means root. */
    user?: string | null;
}
export interface AddHostInput {
    alias: string;
    host: string;
    port?: number;
    username: string;
    authType: AuthType;
    privateKeyPath?: string;
    defaultCwd?: string;
    allowedPaths?: string[];
    editablePaths?: string[];
    services?: HostService[];
    /** Privilege escalation policy; user-managed, never enabled by the model tool. */
    sudo?: SudoInput;
    /** Optional pre-trusted OpenSSH SHA256 fingerprint. */
    hostKeyFingerprint?: string;
    tags?: string[];
    note?: string;
    fingerprintPolicy?: FingerprintPolicy;
    readOnly?: boolean;
}
export interface UpdateHostInput {
    alias?: string;
    host?: string;
    port?: number;
    username?: string;
    authType?: AuthType;
    privateKeyPath?: string;
    defaultCwd?: string | null;
    allowedPaths?: string[];
    editablePaths?: string[];
    services?: HostService[];
    /** Locked for the model tool: only the current policy is accepted. */
    sudo?: SudoInput;
    tags?: string[];
    note?: string | null;
    fingerprintPolicy?: FingerprintPolicy;
    readOnly?: boolean;
}
/**
 * User-driven edit from the local Web page.
 *
 * Unlike {@link UpdateHostInput}, this allows the human to correct locked
 * identity and path fields. It is only reachable through the loopback-only
 * management route; the model-facing `ssh_host_update` tool keeps the locks.
 */
export interface ManagedUpdateInput extends UpdateHostInput {
    /** `null` clears the stored TOFU fingerprint; a value pins it. */
    hostKeyFingerprint?: string | null;
}
export type CredentialStatus = 'available' | 'missing' | 'unavailable';
/** Validate the service directory notes attached to one host. */
export declare function validateServices(value: unknown, index: number | null): HostService[];
/**
 * Turn one management/tool input into a stored policy.
 *
 * `mode: 'off'` (or no input) clears it. The credential reference is always
 * rewritten to the canonical `host:<id>:sudo` key so a host that is edited or
 * re-added can never point at another host's secret.
 */
export declare function normalizeSudoInput(input: SudoInput | undefined, hostId: string): HostSudo | undefined;
/** Validate one persisted host and fill fields added by later versions. */
export declare function normalizeHost(value: unknown, index: number): HostRecord;
/** Derive the redacted model-facing view; never includes key paths or secrets. */
export declare function toHostView(host: HostRecord, credentialStatus: CredentialStatus, sudoPasswordConfigured?: boolean, tempDir?: string | null): HostView;
/** The persisted host inventory. All mutations are serialized. */
export declare class HostStore {
    private readonly dataDir;
    readonly file: string;
    private cache;
    private queue;
    constructor(dataDir: string);
    /** Load once and cache; a manual edit becomes visible on restart or `reload`. */
    load(): Promise<HostRecord[]>;
    /** All hosts in file order. */
    list(): Promise<HostRecord[]>;
    /** Discard the cache so the next read re-parses hosts.json. */
    reload(): Promise<HostRecord[]>;
    /** Find one host by id or alias; the error lists the available aliases. */
    find(ref: string): Promise<HostRecord>;
    add(input: AddHostInput): Promise<HostRecord>;
    update(ref: string, patch: UpdateHostInput): Promise<HostRecord>;
    remove(ref: string): Promise<HostRecord>;
    /**
     * Full user-initiated edit used by the local management page.
     *
     * The page is the human-facing counterpart of `ssh_host_update`: it may fix
     * the address, port, login user, auth type, key path, and path policy. All
     * values are still validated, and changing the connection identity drops the
     * old TOFU fingerprint unless the request pins a new one.
     */
    updateManaged(ref: string, patch: ManagedUpdateInput): Promise<HostRecord>;
    /** Persist a TOFU fingerprint after the first successful handshake. */
    setFingerprint(id: string, sha256: string): Promise<void>;
    private mutate;
    private persist;
}
