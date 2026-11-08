/** Host inventory tools: add, list, update, remove, and connectivity test. */
import type { Context } from '@deepseek-ai/cordis';
import type { ToolDeps } from '../deps.js';
/** Register the five inventory/connectivity tools on the plugin context. */
export declare function registerHostTools(ctx: Context, deps: ToolDeps): void;
/** Keep the host-id/alias contract visible to the tool layer. */
export type { ToolDeps };
