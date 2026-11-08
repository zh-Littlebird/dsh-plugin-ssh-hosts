/**
 * Small helpers shared by this plugin's two Web surfaces.
 *
 * Both the command-history endpoint and the server-management API mount under
 * one prefix route each, so they need the same low-level pieces: prefix route
 * registration that waits for `webServer`, bounded JSON responses, a bounded
 * request body reader, and the loopback/CSRF checks that keep the management
 * API usable only from this machine and this page.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Context } from '@deepseek-ai/cordis';
import type { DebugLogger } from './redact.js';
export interface WebRouteLike {
    kind: 'prefix';
    path: string;
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
}
export interface WebServerLike {
    register(route: WebRouteLike): () => void;
}
export interface PrefixRouteOptions {
    /** Data directory used for the mount-status diagnostics file. */
    dataDir: string;
    /** URL prefix this plugin claims, e.g. `/ssh-hosts-ui`. */
    path: string;
    /** Human name for diagnostics, e.g. `hosts-ui`. */
    name: string;
    /** Diagnostics file name inside `dataDir`. */
    statusFile: string;
    debug: DebugLogger;
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
}
/**
 * Register one prefix route once the `webServer` service is available. A
 * composition without a web server (headless profiles) simply skips it.
 */
export declare function registerPrefixRoute(ctx: Context, options: PrefixRouteOptions): void;
export declare function sendJson(res: ServerResponse, status: number, body: unknown): void;
/** One error shape both Web surfaces and their clients understand. */
export declare function sendError(res: ServerResponse, status: number, error: unknown): void;
/** Pick the HTTP status that matches a structured plugin error. */
export declare function statusForError(error: unknown): number;
/** `true` for 127.0.0.0/8, `::1`, and the IPv4-mapped loopback form. */
export declare function isLoopbackAddress(address: string | undefined): boolean;
/** Reject requests that did not originate on this machine. */
export declare function isLoopbackRequest(req: IncomingMessage): boolean;
/** Only a page served from this machine may write to the management API. */
export declare function isLoopbackOrigin(origin: string): boolean;
/** Read `x-ssh-hosts-ui: 1` through Node's string-or-array header type. */
export declare function hasUiWriteHeader(req: IncomingMessage): boolean;
/** Read a bounded JSON object body; malformed or oversized input is an error. */
export declare function readJsonBody(req: IncomingMessage, maxBytes?: number): Promise<Record<string, unknown>>;
