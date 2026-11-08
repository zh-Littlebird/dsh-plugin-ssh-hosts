/**
 * Credential storage isolated from the host inventory.
 *
 * `file` encrypts each value with AES-256-GCM under a random 32-byte master
 * key kept beside the store (mode 0600, best-effort Windows ACL). This is
 * deliberately not an OS keychain: it prevents accidental reads, not code
 * running as the same user. `env` reads values from the process environment
 * and writes nothing. `none` refuses all secret access.
 */
import type { SecretsBackend } from './types.js';
export interface SecretStoreOptions {
    dir: string;
    backend: SecretsBackend;
    envPrefix: string;
}
/** Stable environment variable name for one credential reference. */
export declare function envNameFor(ref: string, prefix: string): string;
export declare class SecretStore {
    private readonly options;
    readonly credentialsFile: string;
    readonly masterKeyFile: string;
    private queue;
    constructor(options: SecretStoreOptions);
    /** Whether a usable value is present for this reference. */
    status(ref: string): Promise<'available' | 'missing' | 'unavailable'>;
    /** Resolve a secret for one connection; the value stays in this process. */
    get(ref: string): Promise<string | undefined>;
    /** Store or replace one secret. */
    set(ref: string, value: string): Promise<void>;
    /** Remove one secret if present. */
    delete(ref: string): Promise<boolean>;
    /** Remove every credential belonging to one host id. */
    deleteHost(hostId: string): Promise<number>;
    private readDocument;
    private readMasterKey;
    private encrypt;
    private decrypt;
}
