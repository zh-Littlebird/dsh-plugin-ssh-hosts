/**
 * One redaction boundary for everything that leaves the plugin: tool results,
 * errors, audit lines, and debug logs.
 */
/** Remember a secret so it can never appear verbatim in any output. */
export declare function registerSecret(value: string | undefined | null): void;
/** Drop a secret from the in-memory registry. */
export declare function forgetSecret(value: string | undefined | null): void;
/**
 * Redact registered secret values plus well-known credential shapes.
 * Registered values are replaced first, longest first, so overlapping
 * secrets cannot leave a fragment behind.
 */
export declare function redact(text: string): string;
/** Redact an unknown thrown value into one readable line without a stack. */
export declare function redactError(error: unknown): string;
export interface DebugLogger {
    (message: string): void;
}
/** A stderr logger that is silent unless enabled and redacts every line. */
export declare function createDebugLogger(enabled: boolean): DebugLogger;
