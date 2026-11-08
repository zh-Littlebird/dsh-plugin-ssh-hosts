/**
 * Local server-management API behind the Web "SSH 服务器" page.
 *
 * This is the human-facing counterpart of the `ssh_host_*` tools: it can add,
 * fully edit, remove, test, and provision credentials for a host. It is mounted
 * at `/ssh-hosts-ui` on the Harness web server and is deliberately limited to
 * loopback clients; write requests must also carry the page's custom header and
 * a same-machine Origin, which keeps ordinary cross-site requests out.
 *
 * Passwords and key passphrases may be submitted here. They are written only to
 * the encrypted credential store, never returned, audited, or logged.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Context } from '@deepseek-ai/cordis';
import type { AuditLog } from './audit.js';
import type { SshHostsConfig } from './config.js';
import type { HostStore } from './hosts.js';
import type { DebugLogger } from './redact.js';
import type { SecretStore } from './secrets.js';
import type { SshManager } from './ssh.js';
/** URL prefix this API claims on the Harness web server. */
export declare const ROUTE_PREFIX = "/ssh-hosts-ui";
export interface HostsUiOptions {
    dataDir: string;
    config: SshHostsConfig;
    store: HostStore;
    secrets: SecretStore;
    manager: Pick<SshManager, 'test'>;
    audit: AuditLog;
    debug: DebugLogger;
}
/**
 * Build the request handler. Exported so tests can drive it without Cordis.
 */
export declare function createHostsUiHandler(options: HostsUiOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void>;
export interface HostsUiRouteOptions extends HostsUiOptions {
    /** Kept for symmetry with the history route; unused beyond diagnostics. */
    debug: DebugLogger;
}
/** Register the management API once the Harness web server is available. */
export declare function registerHostsUiRoute(ctx: Context, options: HostsUiRouteOptions): void;
