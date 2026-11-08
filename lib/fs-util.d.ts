/** Small filesystem helpers shared by the stores and the transfer tools. */
/** Create a directory (recursively) with a best-effort private mode. */
export declare function ensureDir(dir: string, mode?: number): Promise<void>;
/** Tighten a path to owner-only access. Windows uses a best-effort ACL. */
export declare function hardenPermissions(target: string, mode: number): Promise<void>;
/**
 * Write a file through a uniquely named sibling and rename it into place, so a
 * crash cannot leave a half-written configuration or credential store.
 */
export declare function atomicWriteFile(file: string, data: string | Uint8Array, mode?: number): Promise<void>;
/** Parse a JSON file, reporting path and position for malformed input. */
export declare function readJson<T>(file: string): Promise<T | undefined>;
/** Whether a local path exists. */
export declare function pathExists(path: string): Promise<boolean>;
/** Resolve a user-supplied local path against a root and require containment. */
export declare function resolveInside(root: string, candidate: string): string;
/** Whether `child` is the same path as, or below, `parent`. */
export declare function isPathInside(parent: string, child: string): boolean;
