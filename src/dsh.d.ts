/**
 * Minimal, shape-accurate declarations for the two harness packages this
 * plugin links against at runtime. The harness ships JavaScript only, so the
 * published `.d.ts` files are represented here with just the surface this
 * plugin consumes.
 */
declare module '@deepseek-ai/dsh-tools' {
  export type JsonValue =
    | null
    | boolean
    | number
    | string
    | JsonValue[]
    | { [key: string]: JsonValue }

  export interface TextBlock {
    type: 'text'
    text: string
  }

  export type ContentBlock = TextBlock

  export interface GenericCallView {
    card: 'generic'
    title: string
    kind?: string
    rawInput?: unknown
    content?: ContentBlock[]
    locations?: Array<{ path: string; line?: number }>
  }

  export interface TerminalCallView {
    card: 'terminal'
    title: string
    description?: string
    cwd?: string
  }

  export type ToolCallView = GenericCallView | TerminalCallView

  export interface GenericResultView {
    card: 'generic'
    title?: string
    content?: ContentBlock[]
  }

  export interface TerminalResultView {
    card: 'terminal'
    title?: string
    output?: string
    exitCode?: number
    signal?: string
  }

  export type ToolResultView = GenericResultView | TerminalResultView

  export interface ToolResult {
    content: ContentBlock[]
    isError: boolean
    meta?: JsonValue
  }

  export interface AgentRef {
    readonly id: string
    readonly session?: {
      /** Stable session identity; the approval seam is keyed by it. */
      readonly id: string
      readonly header?: {
        readonly id?: string
        readonly cwd?: string
        /** Present on a delegated child session. */
        readonly parentSession?: string
      }
    }
  }

  export interface ToolRunContext {
    readonly agent?: AgentRef
    readonly callId: string
    readonly signal: AbortSignal
    deferContext(context: unknown): void
    concludeTurn(): void
  }

  export interface ToolDefinition {
    name: string
    description: string
    parameters: Record<string, unknown>
    output: {
      schema: Record<string, unknown>
      render(args: unknown, value: JsonValue): ContentBlock[]
    }
    execute(args: unknown, exec: ToolRunContext): Promise<unknown>
    presentCall?(args: unknown): ToolCallView | undefined
    presentResult?(args: unknown, result: ToolResult): ToolResultView | undefined
    timeoutMs?: number
    isConcurrencySafe?(args: unknown): boolean
  }

  export interface DefineToolOptions<A, O> {
    name: string
    description: string
    parameters: Record<string, unknown>
    output: {
      schema: Record<string, unknown>
      render(args: A, value: O): ContentBlock[]
      presentationMeta?(args: A, value: O): JsonValue
    }
    timeoutMs?: number
    isConcurrencySafe?(args: A): boolean
    execute(args: A, exec: ToolRunContext): Promise<O>
    presentCall?(args: A): ToolCallView | undefined
    presentResult?(args: A, result: ToolResult): ToolResultView | undefined
  }

  export function defineTool<A, O>(options: DefineToolOptions<A, O>): ToolDefinition
}

declare module '@deepseek-ai/cordis' {
  import type { ToolDefinition } from '@deepseek-ai/dsh-tools'

  export interface Context {
    tools: {
      register(definition: ToolDefinition): () => void
    }
    get<T>(name: string): T | undefined
    effect(execute: () => void | (() => void)): () => void
  }
}
