/** Append-only JSONL audit trail with no credential material. */
export type AuditAction = 'exec' | 'read' | 'write' | 'upload' | 'download' | 'test' | 'host_add' | 'host_update' | 'host_remove' | 'credential';
export interface AuditEntry {
    action: AuditAction;
    server: string;
    /**
     * Stable host identity. The alias is a mutable label, so history keeps this
     * id to resolve every past action of one server to its current alias.
     */
    hostId?: string;
    user: string;
    command?: string;
    path?: string;
    exitCode?: number | null;
    durationMs?: number;
    truncated?: boolean;
    approval?: string;
    /** Whether the command ran through the host's configured sudo. */
    privileged?: boolean;
    ok: boolean;
    code?: string;
}
export declare class AuditLog {
    private readonly enabled;
    readonly file: string;
    private queue;
    constructor(dataDir: string, enabled: boolean);
    /** Append one line; rotation is size-based and best effort. */
    append(entry: AuditEntry): Promise<void>;
}
