/** POSIX remote-path resolution, allowlists, and shell quoting. */
export interface RemotePathPolicy {
    home: string;
    cwd: string;
    allowedPaths: string[];
    editablePaths: string[];
    deniedPaths: string[];
    /**
     * Effective scratch directory (already expanded to an absolute path), or
     * null/absent when the `tempDir` grant is disabled. It is informational:
     * it is already folded into {@link allowedPaths} and {@link editablePaths};
     * the messages use it to tell the model where its process files belong.
     */
    tempDir?: string | null;
}
/** Expand `~`, anchor relative paths at `cwd`, and normalize to absolute POSIX form. */
export declare function expandRemotePath(input: string, cwd: string, home: string): string;
/** Whether `target` is `root` or lives below it. */
export declare function isRemoteInside(root: string, target: string): boolean;
/**
 * Expand the configured scratch directory (`tempDir`) against the login home.
 * Returns null for an empty value, which means the grant is disabled.
 */
export declare function resolveTempRoot(tempDir: string | null | undefined, home: string): string | null;
/**
 * Fold the scratch directory into one path list unless a root already covers
 * it (for example `~` or `/`). Returns a copy; the stored host policy is never
 * mutated.
 */
export declare function withTempRoot(roots: string[], tempRoot: string | null, home: string, cwd: string): string[];
/**
 * The scratch grant that actually applies to one host: `deniedPaths` wins, so
 * a host that denies `/tmp` does not get it folded into its policy and the
 * instructions never point the model at a refused directory.
 */
export declare function effectiveTempRoot(tempRoot: string | null, deniedPaths: string[], home: string, cwd: string): string | null;
/** Redirect scratch files to the shared temp directory, when one is granted. */
export declare function tempDirHint(policy: RemotePathPolicy): string | null;
/** Refuse a path outside every allowed root or inside a denied root. */
export declare function assertRemotePathAllowed(target: string, policy: RemotePathPolicy): string;
/** Resolve a user path and enforce the server policy in one step. */
export declare function resolveRemotePath(input: string, policy: RemotePathPolicy): string;
/** Refuse a write target outside every editable root. */
export declare function assertRemoteEditable(target: string, policy: RemotePathPolicy): string;
/** The effective working directory, defaulting to the login home. */
export declare function resolveRemoteCwd(input: string | undefined, policy: Omit<RemotePathPolicy, 'cwd'>): string;
/** Quote one string for a POSIX shell. */
export declare function shellQuote(value: string): string;
/** Run a command in a directory without changing its exit status semantics. */
export declare function wrapCommand(command: string, cwd: string): string;
/**
 * Extract path-like shell tokens. This is a conservative scanner, not a shell
 * parser: it handles quoting and redirections well enough to enforce a denylist
 * and an optional allowlist, and it never rewrites the command.
 */
export declare function extractPathTokens(command: string): string[];
/** Always refuse command arguments that name a denied path. */
export declare function assertCommandPathsAllowed(command: string, policy: RemotePathPolicy, strict: boolean): void;
