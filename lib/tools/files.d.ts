/** Remote file read/write and local↔remote transfer tools. */
import type { Context } from '@deepseek-ai/cordis';
import type { ToolDeps } from '../deps.js';
/** Register the four SFTP tools. */
export declare function registerFileTools(ctx: Context, deps: ToolDeps): void;
