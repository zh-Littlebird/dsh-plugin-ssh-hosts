/** Append-only JSONL audit trail with no credential material. */

import { appendFile, rename, rm, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { ensureDir, hardenPermissions } from './fs-util.js'
import { redact } from './redact.js'

export type AuditAction =
  | 'exec'
  | 'read'
  | 'write'
  | 'upload'
  | 'download'
  | 'test'
  | 'host_add'
  | 'host_update'
  | 'host_remove'
  | 'credential'

export interface AuditEntry {
  action: AuditAction
  server: string
  /**
   * Stable host identity. The alias is a mutable label, so history keeps this
   * id to resolve every past action of one server to its current alias.
   */
  hostId?: string
  user: string
  command?: string
  path?: string
  exitCode?: number | null
  durationMs?: number
  truncated?: boolean
  approval?: string
  /** Whether the command ran through the host's configured sudo. */
  privileged?: boolean
  ok: boolean
  code?: string
}

const MAX_AUDIT_BYTES = 5 * 1024 * 1024

export class AuditLog {
  readonly file: string
  private queue: Promise<unknown> = Promise.resolve()

  constructor(
    dataDir: string,
    private readonly enabled: boolean,
  ) {
    this.file = join(dataDir, 'audit.log')
  }

  /** Append one line; rotation is size-based and best effort. */
  append(entry: AuditEntry): Promise<void> {
    if (!this.enabled) return Promise.resolve()
    const run = this.queue.then(async () => {
      try {
        await ensureDir(dirname(this.file))
        try {
          const info = await stat(this.file)
          if (info.size > MAX_AUDIT_BYTES) {
            await rm(`${this.file}.1`, { force: true })
            await rename(this.file, `${this.file}.1`)
          }
        } catch {
          // No existing log; the append creates it.
        }
        const line = JSON.stringify({
          time: new Date().toISOString(),
          ...entry,
          ...(entry.command === undefined ? {} : { command: redact(entry.command) }),
          ...(entry.path === undefined ? {} : { path: redact(entry.path) }),
        })
        await appendFile(this.file, `${line}\n`, { mode: 0o600 })
        await hardenPermissions(this.file, 0o600)
      } catch (error) {
        process.stderr.write(`[ssh-hosts] audit write failed: ${redact(error instanceof Error ? error.message : String(error))}\n`)
      }
    })
    this.queue = run.catch(() => undefined)
    return run
  }
}
