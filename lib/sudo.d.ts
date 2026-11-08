/**
 * Privilege escalation (`sudo`) support for `ssh_exec`.
 *
 * Two things happen here:
 *
 * 1. A command that literally starts with `sudo …` is recognised and rewritten
 *    so it runs through the plugin's own wrapper (which knows how to supply a
 *    password); `privileged: true` expresses the same intent without typing
 *    `sudo`. sudo flags the plugin cannot reproduce (`-i`, `-s`, `-e`, …) are
 *    reported instead of being silently dropped.
 * 2. The per-host sudo policy is resolved into one {@link ExecPrivilege}: which
 *    mode, which target user, and—for password mode only—the password, which
 *    never leaves this process and is only ever written to the SSH channel's
 *    stdin.
 */
import type { ToolDeps } from './deps.js';
import type { SecretStore } from './secrets.js';
import type { ExecPrivilege } from './ssh.js';
import type { HostRecord } from './types.js';
/** Default credential-store key for a host's sudo password. */
export declare function sudoPasswordRef(hostId: string): string;
/** Where this host's sudo password lives, following the stored reference. */
export declare function sudoSecretRef(host: HostRecord): string | undefined;
/**
 * Whether a usable sudo password exists, without ever reading its value.
 * The login password counts when the host authenticates with a password,
 * because {@link resolveSudoPassword} falls back to it.
 */
export declare function sudoPasswordStatus(options: {
    secrets: Pick<SecretStore, 'status'>;
}, host: HostRecord): Promise<'available' | 'missing' | 'unavailable'>;
/** Conservative POSIX account-name shape for `sudo -u`. */
export declare const SUDO_USER_PATTERN: RegExp;
export interface SudoPrefix {
    /** Whether the command starts with the `sudo` word. */
    privileged: boolean;
    /** The command with the leading `sudo` and its option tokens removed. */
    command: string;
    /** Target user requested with `-u/--user`. */
    user?: string;
    /** sudo flags this plugin cannot reproduce; callers must reject them. */
    unsupported: string[];
}
/**
 * Split a leading `sudo` invocation from the command it runs.
 *
 * The remaining command text is preserved byte for byte (only the leading
 * whitespace is trimmed), so quoting and `&&` chains survive untouched.
 */
export declare function parseSudoPrefix(command: string): SudoPrefix;
/**
 * Resolve the effective privilege for one call.
 *
 * Returns `undefined` for an unprivileged command. Throws when the command
 * asked for root but the host has no usable sudo configuration, so the model
 * gets an actionable error instead of a confusing shell failure.
 */
export declare function resolvePrivilege(deps: ToolDeps, host: HostRecord, request: {
    privileged: boolean;
    user?: string;
}): Promise<ExecPrivilege | undefined>;
