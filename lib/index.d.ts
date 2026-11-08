/**
 * dsh-plugin-ssh-hosts — multiple Linux servers over SSH.
 *
 * The plugin owns its data under `$DSH_HOME/ssh-hosts` (or `dataDir`): the host
 * inventory, an AES-256-GCM credential store, TOFU fingerprints, transfers,
 * and an audit log. Passwords, passphrases, and private-key bytes never enter a
 * tool result, the session log, or a debug line.
 */
import type { Context } from '@deepseek-ai/cordis';
import { Config, resolveDataDir, withDefaults, type SshHostsConfig } from './config.js';
export declare const name = "ssh-hosts";
export declare const inject: string[];
export { Config };
/** Register every `ssh_*` tool and the connection pool's cleanup hook. */
export declare function apply(ctx: Context, rawConfig: Partial<SshHostsConfig> | undefined): void;
export { withDefaults, resolveDataDir };
export type { SshHostsConfig };
