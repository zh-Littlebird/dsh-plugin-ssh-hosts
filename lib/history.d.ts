/**
 * Audit history for humans: read `audit.log` and serve it to the Web panel.
 *
 * The audit log already records every SSH action (command, path, exit code,
 * duration, approval outcome) and never contains credential material. This
 * module only turns that append-only JSONL file into a read-only HTTP view so
 * the user can see what the agent did on the servers without opening a shell
 * or asking the model.
 *
 * An alias is a mutable label. Every entry written by this version carries the
 * stable `hostId`, so history resolves each row to the server's *current* alias
 * and the server filter lists the inventory once — renaming a host never adds
 * another "server" to the panel. Host-management records (`host_add`,
 * `host_update`, `host_remove`, credential edits) stay in `audit.log` for
 * compliance but are not command history, so they are not shown here.
 */
import type { Context } from '@deepseek-ai/cordis';
import type { AuditEntry } from './audit.js';
import type { DebugLogger } from './redact.js';
import type { HostRecord } from './types.js';
/** One audit line, with the timestamp the writer prepended. */
export interface HistoryEntry extends AuditEntry {
    time: string;
    /** Resolved host address (IP/DNS), present when the host still exists. */
    serverIp?: string;
    /** Resolved address group key, `ip:<normalized address>`. */
    serverId?: string;
}
export interface HistoryQuery {
    /** Newest entries to return; clamped to 1..1000. */
    limit?: number | undefined;
    /** Host address (IP/DNS), alias, or stable host id. */
    server?: string | undefined;
    /** Exact action name, or a comma-separated list of them. */
    action?: string | undefined;
    /** Keep only entries that failed. */
    failedOnly?: boolean | undefined;
    /** Case-insensitive substring over command and path. */
    search?: string | undefined;
}
/**
 * One server row in the history filter, grouped by the host address
 * (`host.host`) rather than by alias: renames never add a row, and two
 * host records that point at the same address share one row.
 */
export interface HistoryServer {
    /** Group key, `ip:<normalized address>`. */
    id: string;
    /** Host address exactly as stored in `hosts.json` (IP or DNS name). */
    ip: string;
    /** Entries recorded for this address after the action filter. */
    count: number;
    /** Aliases that currently point at this address. */
    aliases: string[];
}
export interface HistoryPage {
    entries: HistoryEntry[];
    /** Command entries parsed from audit.log plus its rotated predecessor. */
    total: number;
    /** Entries left after filters, before `limit`. */
    matched: number;
    returned: number;
    auditEnabled: boolean;
    dataDir: string;
    generatedAt: string;
    /** Current inventory grouped by host address, one row per IP/DNS name. */
    servers: HistoryServer[];
}
/** URL prefix this plugin claims on the Harness web server. */
export declare const ROUTE_PREFIX = "/ssh-hosts-api";
/**
 * Read the audit trail, newest first. `audit.log.1` is older than `audit.log`
 * because rotation renames the current file aside. `hosts` is the current
 * inventory; it supplies the server rows (grouped by host address) and the
 * address each entry belongs to.
 */
export declare function readHistory(dataDir: string, query?: HistoryQuery, auditEnabled?: boolean, hosts?: HostRecord[]): Promise<HistoryPage>;
export interface HistoryRouteOptions {
    dataDir: string;
    auditEnabled: boolean;
    debug: DebugLogger;
    /** Current inventory; the panel uses it for the address-grouped filter. */
    hosts?: () => Promise<HostRecord[]>;
}
/**
 * Register the read-only history endpoint the Web panel polls. A composition
 * without a web server (headless profiles) simply skips it.
 */
export declare function registerHistoryRoute(ctx: Context, options: HistoryRouteOptions): void;
