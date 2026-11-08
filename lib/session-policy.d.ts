/**
 * Session permission preset detection.
 *
 * The plugin asks the Harness two questions before it gates anything:
 *
 * 1. `approval` — is this session's approval policy `ask` or `never`? Under
 *    `never` no prompt can be shown at all: the approval service rejects every
 *    request deterministically without consulting an answerer.
 * 2. `sandboxPolicy` — is this session's file sandbox `danger-full-access`
 *    (the Web GUI's “完全权限” preset) or one of the restricted modes?
 *
 * Both services are optional: a headless composition may omit them, and the
 * plugin must keep working (fail closed) when it cannot tell. Only the exact
 * `never` value counts as “prompts disabled”; anything unexpected keeps the
 * old `ask` behaviour so a future Harness change can never silently widen
 * permissions.
 */
import type { ToolRunContext } from '@deepseek-ai/dsh-tools';
import type { SessionTrust, TrustResolver } from './deps.js';
export interface TrustReaders {
    approval?: unknown;
    sandbox?: unknown;
}
/**
 * Resolve the effective permission preset for one tool call.
 *
 * `fullAccess` is deliberately narrow: it requires the approval service to say
 * `never` *and* the sandbox to be `danger-full-access` (or absent, meaning no
 * file sandbox is mounted at all). A `never` policy over a restricted sandbox
 * only disables prompts; risky commands then fail closed with an explanation.
 */
export declare function resolveSessionTrust(readers: TrustReaders, exec: ToolRunContext): SessionTrust;
/** Build the resolver the plugin hands to every tool through `ToolDeps`. */
export declare function createTrustResolver(readers: () => TrustReaders): TrustResolver;
/** One-line description used in errors and debug lines. */
export declare function describeTrust(trust: SessionTrust): string;
