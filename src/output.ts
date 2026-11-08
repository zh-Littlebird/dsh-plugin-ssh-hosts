/** Bounded capture that keeps the head and tail of a stream and reports loss. */

export interface CapturedOutput {
  text: string
  bytes: number
  truncated: boolean
  originalBytes: number
}

/**
 * Accumulate at most `limit` bytes while counting everything. Once the limit
 * is crossed, the first half and the most recent half are kept and the elided
 * byte count is rendered between them, so a model can never mistake a clipped
 * stream for a complete one.
 */
export class BoundedOutput {
  private readonly headLimit: number
  private readonly tailLimit: number
  private readonly headChunks: Buffer[] = []
  private readonly tailChunks: Buffer[] = []
  private headBytes = 0
  private tailBytes = 0
  private total = 0

  constructor(private readonly limit: number) {
    const safeLimit = Math.max(16, Math.floor(limit))
    this.headLimit = Math.floor(safeLimit / 2)
    this.tailLimit = safeLimit - this.headLimit
  }

  push(chunk: Buffer): void {
    if (chunk.length === 0) return
    this.total += chunk.length
    let rest = chunk
    if (this.headBytes < this.headLimit) {
      const take = Math.min(this.headLimit - this.headBytes, rest.length)
      this.headChunks.push(rest.subarray(0, take))
      this.headBytes += take
      rest = rest.subarray(take)
    }
    if (rest.length === 0) return
    this.tailChunks.push(rest)
    this.tailBytes += rest.length
    while (this.tailBytes > this.tailLimit && this.tailChunks.length > 0) {
      const excess = this.tailBytes - this.tailLimit
      const first = this.tailChunks[0] as Buffer
      if (first.length <= excess) {
        this.tailChunks.shift()
        this.tailBytes -= first.length
      } else {
        this.tailChunks[0] = first.subarray(excess)
        this.tailBytes -= excess
      }
    }
  }

  get originalBytes(): number {
    return this.total
  }

  get truncated(): boolean {
    return this.total > this.headBytes + this.tailBytes
  }

  /** Materialize the retained text with an explicit middle marker when clipped. */
  capture(): CapturedOutput {
    const head = Buffer.concat(this.headChunks)
    const tail = Buffer.concat(this.tailChunks)
    if (!this.truncated) {
      return {
        text: Buffer.concat([head, tail]).toString('utf8'),
        bytes: this.total,
        truncated: false,
        originalBytes: this.total,
      }
    }
    const omitted = this.total - head.length - tail.length
    const marker = Buffer.from(`\n... [truncated ${omitted} bytes] ...\n`, 'utf8')
    return {
      text: Buffer.concat([head, marker, tail]).toString('utf8'),
      bytes: head.length + marker.length + tail.length,
      truncated: true,
      originalBytes: this.total,
    }
  }
}

/** Human-readable byte count for model-facing renderers. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`
}
