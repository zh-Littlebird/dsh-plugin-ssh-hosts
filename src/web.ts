/**
 * Small helpers shared by this plugin's two Web surfaces.
 *
 * Both the command-history endpoint and the server-management API mount under
 * one prefix route each, so they need the same low-level pieces: prefix route
 * registration that waits for `webServer`, bounded JSON responses, a bounded
 * request body reader, and the loopback/CSRF checks that keep the management
 * API usable only from this machine and this page.
 */

import { mkdirSync, writeFileSync } from 'node:fs'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { DebugLogger } from './redact.js'
import { SshHostsError } from './types.js'

export interface WebRouteLike {
  kind: 'prefix'
  path: string
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
}

export interface WebServerLike {
  register(route: WebRouteLike): () => void
}

/** Cordis runs an `inject` callback once the named services are available. */
interface InjectingContext {
  inject?: (deps: string[], execute: (ctx: Context) => void | (() => void)) => void
}

function resolveWebServer(ctx: Context): WebServerLike | undefined {
  try {
    const viaGet = ctx.get<WebServerLike>('webServer')
    if (viaGet !== undefined) return viaGet
  } catch {
    // A context without a service registry: fall through to the property.
  }
  try {
    return (ctx as unknown as { webServer?: WebServerLike }).webServer
  } catch {
    // Cordis refuses to read a service that was not injected.
    return undefined
  }
}

function writeStatus(dataDir: string, file: string, value: Record<string, unknown>): void {
  try {
    mkdirSync(dataDir, { recursive: true })
    const body = `${JSON.stringify({ at: new Date().toISOString(), ...value }, null, 2)}\n`
    writeFileSync(join(dataDir, file), body, { mode: 0o600 })
  } catch {
    // Diagnostics only; never fail the plugin because of it.
  }
}

export interface PrefixRouteOptions {
  /** Data directory used for the mount-status diagnostics file. */
  dataDir: string
  /** URL prefix this plugin claims, e.g. `/ssh-hosts-ui`. */
  path: string
  /** Human name for diagnostics, e.g. `hosts-ui`. */
  name: string
  /** Diagnostics file name inside `dataDir`. */
  statusFile: string
  debug: DebugLogger
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
}

/**
 * Register one prefix route once the `webServer` service is available. A
 * composition without a web server (headless profiles) simply skips it.
 */
export function registerPrefixRoute(ctx: Context, options: PrefixRouteOptions): void {
  const route: WebRouteLike = { kind: 'prefix', path: options.path, handler: options.handler }

  const attach = (owning: Context, mode: string): (() => void) => {
    const webServer = resolveWebServer(owning)
    if (webServer === undefined) {
      writeStatus(options.dataDir, options.statusFile, {
        ok: false,
        mode,
        name: options.name,
        reason: 'webServer service unavailable',
      })
      options.debug(`${options.name} route not mounted (${mode}): webServer unavailable`)
      return () => {}
    }
    try {
      const dispose = webServer.register(route)
      writeStatus(options.dataDir, options.statusFile, { ok: true, mode, name: options.name, path: options.path })
      options.debug(`${options.name} endpoint mounted at ${options.path} (${mode})`)
      return dispose
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      writeStatus(options.dataDir, options.statusFile, {
        ok: false,
        mode,
        name: options.name,
        reason: `register failed: ${reason}`,
      })
      options.debug(`${options.name} route registration failed (${mode}): ${reason}`)
      return () => {}
    }
  }

  // Cordis refuses to read a service the plugin did not inject, so ask for
  // `webServer` through ctx.inject and register inside that scope.
  const inject = (ctx as unknown as InjectingContext).inject
  if (typeof inject === 'function') {
    writeStatus(options.dataDir, options.statusFile, {
      ok: false,
      mode: 'waiting',
      name: options.name,
      reason: 'waiting for the webServer service',
    })
    inject.call(ctx, ['webServer'], (inner: Context) => attach(inner, 'inject'))
    return
  }
  // Older contexts without inject only work when the service is reflected.
  if (resolveWebServer(ctx) !== undefined) {
    ctx.effect(() => attach(ctx, 'direct'))
    return
  }
  writeStatus(options.dataDir, options.statusFile, {
    ok: false,
    mode: 'none',
    name: options.name,
    reason: 'no ctx.inject and no reflected webServer',
  })
  options.debug(`${options.name} route not mounted: no ctx.inject and no reflected webServer`)
}

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  })
  res.end(text)
}

function stripCode(message: string): string {
  return message.replace(/\s+\[[A-Z0-9_]+\]$/, '')
}

/** One error shape both Web surfaces and their clients understand. */
export function sendError(res: ServerResponse, status: number, error: unknown): void {
  if (error instanceof SshHostsError) {
    sendJson(res, status, {
      error: { code: error.code, message: stripCode(error.message), hint: error.hint },
    })
    return
  }
  const message = error instanceof Error ? error.message : String(error)
  sendJson(res, status, { error: { code: 'INTERNAL', message: message.length === 0 ? '请求失败' : message, hint: null } })
}

/** Pick the HTTP status that matches a structured plugin error. */
export function statusForError(error: unknown): number {
  if (!(error instanceof SshHostsError)) return 500
  if (error.code === 'HOST_NOT_FOUND' || error.code === 'NOT_FOUND') return 404
  if (error.code === 'HOST_ALIAS_EXISTS' || error.code === 'HISTORY_UNAVAILABLE') {
    return error.code === 'HOST_ALIAS_EXISTS' ? 409 : 500
  }
  if (error.code === 'BODY_TOO_LARGE') return 413
  if (error.code === 'METHOD_NOT_ALLOWED') return 405
  if (error.code === 'FORBIDDEN') return 403
  return 400
}

/** `true` for 127.0.0.0/8, `::1`, and the IPv4-mapped loopback form. */
export function isLoopbackAddress(address: string | undefined): boolean {
  if (address === undefined) return false
  return address === '::1' || address === '::ffff:127.0.0.1' || address.startsWith('127.')
}

/** Reject requests that did not originate on this machine. */
export function isLoopbackRequest(req: IncomingMessage): boolean {
  return isLoopbackAddress(req.socket?.remoteAddress ?? undefined)
}

/** Only a page served from this machine may write to the management API. */
export function isLoopbackOrigin(origin: string): boolean {
  try {
    const url = new URL(origin)
    return url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]' || url.hostname === '::1'
  } catch {
    return false
  }
}

/** Read `x-ssh-hosts-ui: 1` through Node's string-or-array header type. */
export function hasUiWriteHeader(req: IncomingMessage): boolean {
  const header = req.headers['x-ssh-hosts-ui']
  return Array.isArray(header) ? header[0] === '1' : header === '1'
}

const DEFAULT_MAX_BODY = 1024 * 1024

/** Read a bounded JSON object body; malformed or oversized input is an error. */
export async function readJsonBody(req: IncomingMessage, maxBytes = DEFAULT_MAX_BODY): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string)
    total += buffer.length
    if (total > maxBytes) {
      throw new SshHostsError('BODY_TOO_LARGE', '请求体过大', '请缩小表单内容后重试')
    }
    chunks.push(buffer)
  }
  const text = Buffer.concat(chunks).toString('utf8').trim()
  if (text.length === 0) return {}
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new SshHostsError('INVALID_BODY', '请求体不是合法 JSON', '请刷新页面后重试')
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SshHostsError('INVALID_BODY', '请求体必须是 JSON 对象', '请刷新页面后重试')
  }
  return value as Record<string, unknown>
}
