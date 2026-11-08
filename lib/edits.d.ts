/**
 * Best-effort detection of shell commands that write files. A shell cannot be
 * confined without OS-level permissions; this guard makes the common forms
 * (`>`, tee, sed -i, cp/mv/rm/touch, package managers) honor editablePaths.
 */
import { type RemotePathPolicy } from './paths.js';
/** Whether the command appears to write to the remote filesystem. */
export declare function detectCommandEdit(command: string): {
    edits: boolean;
    matched: string[];
};
/**
 * Refuse an edit-like command unless its cwd and every path-like argument are
 * inside the host's editablePaths. Disable with `guardCommandEdits: false`.
 */
export declare function assertCommandEditsAllowed(command: string, policy: RemotePathPolicy): void;
