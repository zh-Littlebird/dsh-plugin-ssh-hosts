/** The command-execution tool: risk gate, sudo, timeout, bounded output, audit. */
import { defineTool } from '@deepseek-ai/dsh-tools';
import type { ToolDeps } from '../deps.js';
/** Register `ssh_exec`. */
export declare function registerExecTool(ctx: {
    tools: {
        register(definition: ReturnType<typeof defineTool>): () => void;
    };
}, deps: ToolDeps): void;
