/** Bounded capture that keeps the head and tail of a stream and reports loss. */
export interface CapturedOutput {
    text: string;
    bytes: number;
    truncated: boolean;
    originalBytes: number;
}
/**
 * Accumulate at most `limit` bytes while counting everything. Once the limit
 * is crossed, the first half and the most recent half are kept and the elided
 * byte count is rendered between them, so a model can never mistake a clipped
 * stream for a complete one.
 */
export declare class BoundedOutput {
    private readonly limit;
    private readonly headLimit;
    private readonly tailLimit;
    private readonly headChunks;
    private readonly tailChunks;
    private headBytes;
    private tailBytes;
    private total;
    constructor(limit: number);
    push(chunk: Buffer): void;
    get originalBytes(): number;
    get truncated(): boolean;
    /** Materialize the retained text with an explicit middle marker when clipped. */
    capture(): CapturedOutput;
}
/** Human-readable byte count for model-facing renderers. */
export declare function formatBytes(bytes: number): string;
