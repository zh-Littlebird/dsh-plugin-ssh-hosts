/** Local-side path confinement for upload and download. */
import type { ToolRunContext } from '@deepseek-ai/dsh-tools';
import type { SshHostsConfig } from './config.js';
import type { ToolDeps } from './deps.js';
/** Roots a transfer may read from or write to: session workspace, config, transfers. */
export declare function localRoots(deps: ToolDeps, exec: ToolRunContext): string[];
/** Resolve a model-supplied local path and require it to stay inside a root. */
export declare function resolveLocalPath(input: string, roots: readonly string[], config: SshHostsConfig): string;
