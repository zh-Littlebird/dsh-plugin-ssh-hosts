/**
 * SSH transport: pooled connections, host-key trust, command execution with
 * bounded output and timeouts, and SFTP file operations constrained by the
 * server's path policy.
 */

import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { mkdir, rename, rm, stat as localStat } from 'node:fs/promises'
import { dirname, posix } from 'node:path'
import { pipeline } from 'node:stream/promises'
import ssh2 from 'ssh2'
import type { Client as SshClient, ClientChannel, ConnectConfig, SFTPWrapper, Stats as SftpStats } from 'ssh2'
import type { SshHostsConfig } from './config.js'
import type { DebugLogger } from './redact.js'
import type { ExecResult, HostRecord, SudoMode, TestResult } from './types.js'
import { SshHostsError } from './types.js'
import { formatBytes, BoundedOutput } from './output.js'
import {
  assertCommandPathsAllowed,
  assertRemoteEditable,
  assertRemotePathAllowed,
  effectiveTempRoot,
  expandRemotePath,
  isRemoteInside,
  resolveRemoteCwd,
  resolveRemotePath,
  resolveTempRoot,
  shellQuote,
  withTempRoot,
  wrapCommand,
  type RemotePathPolicy,
} from './paths.js'
import { assertCommandEditsAllowed } from './edits.js'

export interface ResolvedCredentials {
  password?: string
  privateKey?: Buffer
  passphrase?: string
}

const { Client } = ssh2

export type CredentialResolver = (host: HostRecord) => Promise<ResolvedCredentials>

export interface SshManagerOptions {
  config: SshHostsConfig
  credentials: CredentialResolver
  onFingerprint: (host: HostRecord, fingerprint: string) => Promise<void>
  debug: DebugLogger
}

interface HostKeyObservation {
  fingerprint: string | null
  status: 'unknown' | 'matched' | 'learned' | 'changed'
}

interface ConnectionEntry {
  key: string
  host: HostRecord
  client: SshClient
  fingerprint: string
  hostKeyStatus: 'matched' | 'learned'
  banner: string | null
  home: string
  lastUsed: number
  active: number
  idleTimer: NodeJS.Timeout | null
  sftp: SFTPWrapper | null
  sftpPending: Promise<SFTPWrapper> | null
  closed: boolean
}

interface ExecOptions {
  cwd?: string
  timeoutMs?: number
  maxOutputBytes?: number
  signal?: AbortSignal
  /** Run the command through the host's configured sudo. */
  privilege?: ExecPrivilege
}

/** Resolved privilege escalation for one command. */
export interface ExecPrivilege {
  mode: SudoMode
  /** Target account; `root` when omitted. */
  user?: string
  /** Password for `mode: 'password'`; written to stdin, never logged. */
  password?: string
}

interface WriteOptions {
  createDirs?: boolean
  overwrite?: boolean
}

/** OpenSSH-style SHA256 fingerprint over the raw host key blob. */
export function hostKeyFingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`
}

/**
 * Wrap one command so it runs under the host's configured sudo.
 *
 * The `cd` stays outside `sudo` so the working directory is resolved by the
 * login user and inherited by the privileged shell (sudo never changes cwd).
 * `-S` reads the password from stdin, `-k` forces a fresh authentication so a
 * cached timestamp can never swallow the password line meant for sudo, `-H`
 * points `$HOME` at the target account, and `-p ""` hides the prompt text.
 * `-n` (nopasswd mode) fails immediately instead of waiting for input.
 */
export function wrapPrivilegedCommand(command: string, cwd: string, privilege: ExecPrivilege): string {
  const flags = privilege.mode === 'password' ? '-S -k -H -p ""' : '-n -H -p ""'
  const user = privilege.user === undefined || privilege.user === 'root' ? '' : ` -u ${shellQuote(privilege.user)}`
  return wrapCommand(`sudo ${flags}${user} -- sh -c ${shellQuote(command)}`, cwd)
}

/** Per-host concurrency limiter. */
class Semaphore {
  private active = 0
  private readonly waiters: Array<() => void> = []

  constructor(private readonly limit: number) {}

  async acquire(): Promise<() => void> {
    if (this.active < this.limit) {
      this.active++
      return this.releaseOnce()
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve))
    this.active++
    return this.releaseOnce()
  }

  private releaseOnce(): () => void {
    let released = false
    return () => {
      if (released) return
      released = true
      this.active--
      const next = this.waiters.shift()
      if (next !== undefined) next()
    }
  }
}

function sftpStat(sftp: SFTPWrapper, path: string): Promise<SftpStats> {
  return new Promise((resolve, reject) => {
    sftp.stat(path, (error, stats) => (error ? reject(error) : resolve(stats)))
  })
}

function sftpRealpath(sftp: SFTPWrapper, path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    sftp.realpath(path, (error, absolute) => (error ? reject(error) : resolve(absolute)))
  })
}

function sftpReadFile(sftp: SFTPWrapper, path: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    sftp.readFile(path, (error, data) => (error ? reject(error) : resolve(data)))
  })
}

function sftpWriteFile(sftp: SFTPWrapper, path: string, data: string | Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.writeFile(path, data, (error) => (error ? reject(error) : resolve()))
  })
}

function sftpMkdir(sftp: SFTPWrapper, path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.mkdir(path, (error) => (error ? reject(error) : resolve()))
  })
}

function classify(error: unknown, phase: 'connect' | 'exec' | 'sftp'): SshHostsError {
  if (error instanceof SshHostsError) return error
  const candidate = error as { code?: unknown; message?: unknown; level?: unknown }
  const code = typeof candidate.code === 'string' ? candidate.code : ''
  const level = typeof candidate.level === 'string' ? candidate.level : ''
  const message = typeof candidate.message === 'string' ? candidate.message : String(error)
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return new SshHostsError('DNS_FAILED', '无法解析服务器主机名', '请检查主机地址与 DNS 配置', error)
  }
  if (code === 'ECONNREFUSED') {
    return new SshHostsError('CONNECTION_REFUSED', '服务器拒绝连接', '请确认 SSH 服务已启动、端口正确且防火墙放行', error)
  }
  if (code === 'ETIMEDOUT' || level === 'client-timeout' || /timed? ?out/i.test(message)) {
    return new SshHostsError('CONNECT_TIMEOUT', '连接 SSH 服务器超时', '请检查网络、端口和服务器负载', error)
  }
  if (level === 'client-authentication' || /authentication|all configured authentication methods failed/i.test(message)) {
    return new SshHostsError('AUTH_FAILED', 'SSH 认证失败', '请核对用户名与密码/私钥，并确认该服务器允许对应认证方式', error)
  }
  if (level === 'client-socket' || code === 'ECONNRESET' || code === 'EPIPE') {
    return new SshHostsError('CONNECTION_LOST', 'SSH 连接已断开', '请重试；若持续失败请检查服务器端连接限制', error)
  }
  if (/Host verification failed|host key/i.test(message)) {
    return new SshHostsError('HOST_KEY_UNTRUSTED', 'SSH 主机密钥未通过校验', '请核对服务器指纹；首次连接需使用 accept-new 或由用户确认指纹', error)
  }
  if (phase === 'exec' && /channel|open failed/i.test(message)) {
    return new SshHostsError('CHANNEL_OPEN_FAILED', '无法打开 SSH 执行通道', '服务器可能限制了会话数或禁止 exec，请稍后重试', error)
  }
  return new SshHostsError('SSH_FAILED', `SSH ${phase === 'sftp' ? '文件传输' : phase === 'exec' ? '命令执行' : '连接'}失败`, '请检查服务器状态与网络后重试', error)
}

/** The connection pool and all remote operations, owned by one plugin context. */
export class SshManager {
  private readonly pool = new Map<string, ConnectionEntry>()
  private readonly pending = new Map<string, Promise<ConnectionEntry>>()
  private readonly semaphores = new Map<string, Semaphore>()
  private disposed = false

  constructor(private readonly options: SshManagerOptions) {}

  /** Close every pooled connection and stop idle timers. */
  async dispose(): Promise<void> {
    this.disposed = true
    const entries = [...this.pool.values()]
    this.pool.clear()
    await Promise.all(entries.map((entry) => this.closeEntry(entry)))
  }

  /** Connect, authenticate, learn the home directory, and report trust status. */
  async test(host: HostRecord): Promise<TestResult> {
    const started = Date.now()
    try {
      const entry = await this.open(host)
      const result: TestResult = {
        server: host.alias,
        reachable: true,
        authOk: true,
        hostKeyFingerprint: entry.fingerprint,
        hostKeyStatus: entry.hostKeyStatus,
        banner: entry.banner,
        homeDir: entry.home,
        durationMs: Date.now() - started,
        error: null,
      }
      await this.closeEntry(entry)
      return result
    } catch (error) {
      const failure = classify(error, 'connect')
      const fingerprint = failure.fingerprint
      return {
        server: host.alias,
        reachable: !['DNS_FAILED', 'CONNECTION_REFUSED', 'CONNECT_TIMEOUT'].includes(failure.code),
        authOk: false,
        hostKeyFingerprint: fingerprint,
        hostKeyStatus: failure.code === 'HOST_KEY_MISMATCH' ? 'changed' : failure.code === 'HOST_KEY_UNKNOWN' ? 'unknown' : 'not-checked',
        banner: null,
        homeDir: null,
        durationMs: Date.now() - started,
        error: {
          code: failure.code,
          message: failure.message,
          hint: failure.hint,
        },
      }
    }
  }

  /** Execute one command on the server; a non-zero exit is a normal result. */
  async exec(host: HostRecord, command: string, options: ExecOptions = {}): Promise<ExecResult> {
    if (command.trim().length === 0) {
      throw new SshHostsError('INVALID_COMMAND', '命令不能为空', '请提供要执行的 shell 命令')
    }
    const timeoutMs = Math.min(
      Math.max(1, Math.floor(options.timeoutMs ?? this.options.config.timeoutMs)),
      this.options.config.maxTimeoutMs,
    )
    const outputLimit = Math.max(
      1,
      Math.min(Math.floor(options.maxOutputBytes ?? this.options.config.maxOutputBytes), 16 * 1024 * 1024),
    )
    return this.withEntry(host, async (entry) => {
      const policy = this.policyFor(host, entry.home, options.cwd)
      const privilege = options.privilege
      assertCommandPathsAllowed(command, policy, this.options.config.strictCommandPaths)
      // A privileged command writes with root's authority; the editablePaths
      // guard protects the login user's files and would make every real sudo
      // task fail. deniedPaths and strictCommandPaths still apply.
      if (privilege === undefined && this.options.config.guardCommandEdits) {
        assertCommandEditsAllowed(command, policy)
      }
      const started = Date.now()
      const stdout = new BoundedOutput(outputLimit)
      const stderr = new BoundedOutput(outputLimit)
      let timedOut = false
      let exitCode: number | null = null
      let abortReason: unknown = null
      const wrapped =
        privilege === undefined
          ? wrapCommand(command, policy.cwd)
          : wrapPrivilegedCommand(command, policy.cwd, privilege)

      const execution = await new Promise<{
        exitCode: number | null
        timedOut: boolean
        aborted: boolean
      }>((resolve, reject) => {
        let settled = false
        let killTimer: NodeJS.Timeout | null = null
        let hardTimer: NodeJS.Timeout | null = null
        let channel: ClientChannel | null = null
        const finish = (code: number | null): void => {
          if (settled) return
          settled = true
          if (killTimer !== null) clearTimeout(killTimer)
          if (hardTimer !== null) clearTimeout(hardTimer)
          options.signal?.removeEventListener('abort', onAbort)
          resolve({ exitCode: code, timedOut, aborted: abortReason !== null })
        }
        const fail = (error: unknown): void => {
          if (settled) return
          settled = true
          if (killTimer !== null) clearTimeout(killTimer)
          if (hardTimer !== null) clearTimeout(hardTimer)
          options.signal?.removeEventListener('abort', onAbort)
          reject(classify(error, 'exec'))
        }
        const stopChannel = (): void => {
          if (settled) return
          try {
            channel?.destroy()
          } catch {
            // The channel may already be gone.
          }
          if (killTimer === null) {
            killTimer = setTimeout(() => finish(exitCode), 300)
          }
        }
        const onAbort = (): void => {
          abortReason = options.signal?.reason ?? new Error('aborted')
          stopChannel()
        }
        hardTimer = setTimeout(() => {
          timedOut = true
          stopChannel()
        }, timeoutMs)
        try {
          entry.client.exec(wrapped, { pty: false }, (error, stream) => {
            if (error) {
              fail(error)
              return
            }
            channel = stream
            if (settled) {
              stream.destroy()
              return
            }
            // Hand the sudo password to the channel's stdin and then close it:
            // `sudo -S -k` reads exactly one line, and any command that tries
            // to read stdin afterwards sees EOF instead of hanging.
            if (privilege?.password !== undefined) {
              try {
                stream.write(`${privilege.password}\n`)
                stream.end()
              } catch {
                // A dead channel is reported by the close/error handlers.
              }
            }
            stream.on('data', (chunk: Buffer) => stdout.push(chunk))
            stream.stderr.on('data', (chunk: Buffer) => stderr.push(chunk))
            stream.on('exit', (code: number | null) => {
              exitCode = typeof code === 'number' ? code : null
            })
            stream.on('close', (code: number | null) => {
              finish(typeof code === 'number' ? code : exitCode)
            })
            stream.on('error', (streamError: Error) => {
              if (timedOut || abortReason !== null) return
              fail(streamError)
            })
          })
        } catch (error) {
          fail(error)
        }
        if (settled) return
        if (options.signal?.aborted === true) onAbort()
        else options.signal?.addEventListener('abort', onAbort, { once: true })
      }).catch((error: unknown) => {
        if (abortReason !== null) {
          throw new SshHostsError('ABORTED', 'SSH 命令已取消', '调用方中止了本次执行', error)
        }
        throw error
      })

      const out = stdout.capture()
      const err = stderr.capture()
      if (execution.aborted) {
        throw new SshHostsError('ABORTED', 'SSH 命令已取消', '调用方中止了本次执行')
      }
      const result: ExecResult = {
        server: host.alias,
        command,
        cwd: policy.cwd,
        exitCode: execution.exitCode,
        stdout: out.text,
        stderr: err.text,
        durationMs: Date.now() - started,
        timedOut: execution.timedOut,
        truncated: out.truncated || err.truncated,
        originalBytes: out.originalBytes + err.originalBytes,
        approval: 'not-required',
        privileged: privilege !== undefined,
        privilegeMode: privilege?.mode ?? null,
      }
      this.options.debug(
        `exec ${host.alias} exit=${String(result.exitCode)} ${result.durationMs}ms out=${formatBytes(result.originalBytes)}` +
          `${result.timedOut ? ' timed-out' : ''}${result.truncated ? ' truncated' : ''}` +
          `${privilege === undefined ? '' : ` sudo=${privilege.mode}${privilege.user === undefined ? '' : `:${privilege.user}`}`}`,
      )
      return result
    })
  }

  /** Read a remote text file, refusing binary content and capping bytes. */
  async readFile(host: HostRecord, input: string, maxBytes: number): Promise<{ content: string; bytes: number; originalBytes: number; truncated: boolean; path: string }> {
    const limit = Math.max(1, Math.min(Math.floor(maxBytes), this.options.config.maxTransferBytes))
    return this.withEntry(host, async (entry) => {
      const sftp = await this.getSftp(entry)
      const policy = this.policyFor(host, entry.home)
      const target = resolveRemotePath(input, policy)
      await this.verifyRealPath(sftp, target, policy)
      const info = await sftpStat(sftp, target)
      if (info.isDirectory()) throw new SshHostsError('IS_DIRECTORY', `远程路径是目录：${target}`, '请读取具体文件')
      if (info.size > this.options.config.maxTransferBytes) {
        throw new SshHostsError(
          'FILE_TOO_LARGE',
          `文件超过传输上限：${formatBytes(info.size)}`,
          `maxTransferBytes = ${formatBytes(this.options.config.maxTransferBytes)}；请改用 ssh_download`,
        )
      }
      const truncated = info.size > limit
      let buffer: Buffer
      if (truncated) {
        const stream = sftp.createReadStream(target, { start: 0, end: Math.max(0, limit - 1) })
        const chunks: Buffer[] = []
        await new Promise<void>((resolve, reject) => {
          stream.on('data', (chunk: Buffer) => chunks.push(chunk))
          stream.on('error', reject)
          stream.on('end', resolve)
        })
        buffer = Buffer.concat(chunks)
      } else {
        buffer = await sftpReadFile(sftp, target)
      }
      if (buffer.includes(0)) {
        throw new SshHostsError('BINARY_FILE', `远程文件看起来是二进制：${target}`, '请改用 ssh_download 下载后处理')
      }
      return {
        content: buffer.toString('utf8'),
        bytes: buffer.length,
        originalBytes: info.size,
        truncated,
        path: target,
      }
    })
  }

  /** Create or replace a remote text file after permission and path checks. */
  async writeFile(host: HostRecord, input: string, content: string, options: WriteOptions = {}): Promise<{ path: string; bytesWritten: number; created: boolean; overwritten: boolean }> {
    if (host.readOnly) throw new SshHostsError('READ_ONLY', `服务器 ${host.alias} 处于只读模式`, '请由用户关闭该服务器的 readOnly')
    const payload = Buffer.from(content, 'utf8')
    if (payload.length > this.options.config.maxTransferBytes) {
      throw new SshHostsError('FILE_TOO_LARGE', '写入内容超过传输上限', `maxTransferBytes = ${formatBytes(this.options.config.maxTransferBytes)}`)
    }
    return this.withEntry(host, async (entry) => {
      const sftp = await this.getSftp(entry)
      const policy = this.policyFor(host, entry.home)
      const target = assertRemoteEditable(resolveRemotePath(input, policy), policy)
      if (options.createDirs === true) {
        await this.verifyExistingAncestor(sftp, dirname(target), policy)
        await this.mkdirp(sftp, dirname(target))
      }
      await this.verifyRealPath(sftp, dirname(target), policy, true, 'edit')
      const exists = await sftpStat(sftp, target).catch(() => undefined)
      if (exists !== undefined) {
        if (exists.isDirectory()) throw new SshHostsError('IS_DIRECTORY', `远程路径是目录：${target}`, '请指定文件名')
        if (options.overwrite === false) {
          throw new SshHostsError('FILE_EXISTS', `远程文件已存在：${target}`, '如需覆盖请显式设置 overwrite=true')
        }
        await this.verifyRealPath(sftp, target, policy, false, 'edit')
      }
      await sftpWriteFile(sftp, target, payload)
      return { path: target, bytesWritten: payload.length, created: exists === undefined, overwritten: exists !== undefined }
    })
  }

  /** Stream one local file to the server. */
  async upload(host: HostRecord, localPath: string, remoteInput: string, options: WriteOptions = {}): Promise<{ remotePath: string; bytes: number; overwritten: boolean }> {
    if (host.readOnly) throw new SshHostsError('READ_ONLY', `服务器 ${host.alias} 处于只读模式`, '请由用户关闭该服务器的 readOnly')
    const info = await localStat(localPath)
    if (!info.isFile()) throw new SshHostsError('LOCAL_NOT_FILE', `本地路径不是文件：${localPath}`, '请指定一个本地文件')
    if (info.size > this.options.config.maxTransferBytes) {
      throw new SshHostsError('FILE_TOO_LARGE', `本地文件超过传输上限：${formatBytes(info.size)}`, `maxTransferBytes = ${formatBytes(this.options.config.maxTransferBytes)}`)
    }
    return this.withEntry(host, async (entry) => {
      const sftp = await this.getSftp(entry)
      const policy = this.policyFor(host, entry.home)
      const target = assertRemoteEditable(resolveRemotePath(remoteInput, policy), policy)
      if (options.createDirs === true) {
        await this.verifyExistingAncestor(sftp, dirname(target), policy)
        await this.mkdirp(sftp, dirname(target))
      }
      await this.verifyRealPath(sftp, dirname(target), policy, true, 'edit')
      const exists = await sftpStat(sftp, target).catch(() => undefined)
      if (exists !== undefined && options.overwrite === false) {
        throw new SshHostsError('FILE_EXISTS', `远程文件已存在：${target}`, '如需覆盖请显式设置 overwrite=true')
      }
      if (exists?.isDirectory() === true) throw new SshHostsError('IS_DIRECTORY', `远程路径是目录：${target}`, '请指定目标文件名')
      if (exists !== undefined) await this.verifyRealPath(sftp, target, policy, false, 'edit')
      const remoteStream = sftp.createWriteStream(target)
      await pipeline(createReadStream(localPath), remoteStream)
      return { remotePath: target, bytes: info.size, overwritten: exists !== undefined }
    })
  }

  /** Stream one remote file to a local path through a temporary sibling. */
  async download(host: HostRecord, remoteInput: string, localPath: string, options: WriteOptions = {}): Promise<{ remotePath: string; bytes: number; overwritten: boolean }> {
    return this.withEntry(host, async (entry) => {
      const sftp = await this.getSftp(entry)
      const policy = this.policyFor(host, entry.home)
      const target = resolveRemotePath(remoteInput, policy)
      await this.verifyRealPath(sftp, target, policy)
      const info = await sftpStat(sftp, target)
      if (info.isDirectory()) throw new SshHostsError('IS_DIRECTORY', `远程路径是目录：${target}`, '请指定具体文件')
      if (info.size > this.options.config.maxTransferBytes) {
        throw new SshHostsError('FILE_TOO_LARGE', `远程文件超过传输上限：${formatBytes(info.size)}`, `maxTransferBytes = ${formatBytes(this.options.config.maxTransferBytes)}`)
      }
      await mkdir(dirname(localPath), { recursive: true })
      const existing = await localStat(localPath).catch(() => undefined)
      if (existing !== undefined && options.overwrite === false) {
        throw new SshHostsError('LOCAL_FILE_EXISTS', `本地文件已存在：${localPath}`, '如需覆盖请显式设置 overwrite=true')
      }
      const temp = `${localPath}.ssh-hosts-${process.pid}-${Date.now()}.tmp`
      try {
        await pipeline(sftp.createReadStream(target), createWriteStream(temp, { mode: 0o600 }))
        await rename(temp, localPath)
      } catch (error) {
        await rm(temp, { force: true }).catch(() => undefined)
        throw error
      }
      return { remotePath: target, bytes: info.size, overwritten: existing !== undefined }
    })
  }

  /**
   * Build the effective path policy for one host and optional cwd.
   *
   * The plugin-level `tempDir` (default `/tmp`) is folded into both lists so
   * the model has one predictable scratch place on every server instead of
   * writing process files into service directories. `deniedPaths` still wins,
   * and a disabled `tempDir` restores the per-host policy exactly.
   */
  policyFor(host: HostRecord, home: string, cwd?: string): RemotePathPolicy {
    const tempRoot = effectiveTempRoot(resolveTempRoot(this.options.config.tempDir, home), host.deniedPaths, home, home)
    const base = {
      home,
      allowedPaths: withTempRoot(host.allowedPaths, tempRoot, home, home),
      editablePaths: withTempRoot(host.editablePaths, tempRoot, home, home),
      deniedPaths: host.deniedPaths,
      tempDir: tempRoot,
    }
    const resolvedCwd = resolveRemoteCwd(cwd ?? host.defaultCwd, base)
    return { ...base, cwd: resolvedCwd }
  }

  private async withEntry<T>(host: HostRecord, operation: (entry: ConnectionEntry) => Promise<T>): Promise<T> {
    if (this.disposed) throw new SshHostsError('DISPOSED', 'SSH 插件已卸载', '请重新加载插件')
    const release = await this.semaphoreFor(host.id).acquire()
    try {
      const entry = await this.getEntry(host)
      entry.active++
      entry.lastUsed = Date.now()
      this.scheduleIdle(entry)
      try {
        return await operation(entry)
      } catch (error) {
        if (isConnectionLoss(error)) this.drop(host.id, entry)
        throw error
      } finally {
        entry.active--
        entry.lastUsed = Date.now()
        this.scheduleIdle(entry)
      }
    } finally {
      release()
    }
  }

  private semaphoreFor(hostId: string): Semaphore {
    let semaphore = this.semaphores.get(hostId)
    if (semaphore === undefined) {
      semaphore = new Semaphore(this.options.config.maxConcurrentPerHost)
      this.semaphores.set(hostId, semaphore)
    }
    return semaphore
  }

  private connectionKey(host: HostRecord): string {
    return [
      host.id,
      host.host,
      String(host.port),
      host.username,
      host.auth.type,
      host.auth.type === 'password' ? host.auth.secretRef : host.auth.privateKeyPath,
      host.auth.type === 'key' ? host.auth.passphraseRef ?? '' : '',
      host.fingerprintPolicy,
    ].join('|')
  }

  private async getEntry(host: HostRecord): Promise<ConnectionEntry> {
    const key = this.connectionKey(host)
    const existing = this.pool.get(host.id)
    if (existing !== undefined) {
      if (!existing.closed && existing.key === key) return existing
      this.drop(host.id, existing)
    }
    const pending = this.pending.get(host.id)
    if (pending !== undefined) {
      const entry = await pending
      if (entry.key === key) return entry
    }
    const opening = this.open(host, key).finally(() => {
      this.pending.delete(host.id)
    })
    this.pending.set(host.id, opening)
    const entry = await opening
    if (this.disposed) {
      await this.closeEntry(entry)
      throw new SshHostsError('DISPOSED', 'SSH 插件已卸载', '请重新加载插件')
    }
    this.pool.set(host.id, entry)
    return entry
  }

  private async open(host: HostRecord, key = this.connectionKey(host)): Promise<ConnectionEntry> {
    const credentials = await this.options.credentials(host)
    const observation: HostKeyObservation = { fingerprint: null, status: 'unknown' }
    const client = new Client()
    let banner: string | null = null
    client.on('banner', (message: string) => {
      banner = message
    })
    const config: ConnectConfig = {
      host: host.host,
      port: host.port,
      username: host.username,
      readyTimeout: this.options.config.connectTimeoutMs,
      keepaliveInterval: 15_000,
      keepaliveCountMax: 3,
      hostVerifier: (hostKey: Buffer): boolean => {
        const fingerprint = hostKeyFingerprint(hostKey)
        observation.fingerprint = fingerprint
        if (host.fingerprint === null) {
          if (host.fingerprintPolicy === 'accept-new') {
            observation.status = 'learned'
            return true
          }
          observation.status = 'unknown'
          return false
        }
        if (host.fingerprint.sha256 === fingerprint) {
          observation.status = 'matched'
          return true
        }
        observation.status = 'changed'
        return false
      },
      ...(credentials.password === undefined ? {} : { password: credentials.password, tryKeyboard: true }),
      ...(credentials.privateKey === undefined ? {} : { privateKey: credentials.privateKey }),
      ...(credentials.passphrase === undefined ? {} : { passphrase: credentials.passphrase }),
    }
    if (credentials.password !== undefined) {
      const password = credentials.password
      client.on('keyboard-interactive', (_name: string, _instructions: string, _language: string, prompts: unknown[], finish: (responses: string[]) => void) => {
        finish(prompts.map(() => password))
      })
    }
    try {
      await new Promise<void>((resolve, reject) => {
        let settled = false
        client.once('ready', () => {
          if (settled) return
          settled = true
          resolve()
        })
        client.once('error', (error: Error) => {
          if (settled) return
          settled = true
          reject(error)
        })
        client.connect(config)
      })
    } catch (error) {
      client.end()
      if (observation.status === 'changed') {
        throw new SshHostsError(
          'HOST_KEY_MISMATCH',
          `SSH 主机密钥不匹配：${host.alias}`,
          `旧指纹 ${host.fingerprint?.sha256 ?? '（无）'} / 新指纹 ${observation.fingerprint ?? '（未取得）'}；` +
            '若确认服务器已重装，请由用户删除该主机后重新添加，或把 fingerprintPolicy 改为 accept-new 并清除旧指纹后重连',
          error,
          observation.fingerprint,
        )
      }
      if (observation.status === 'unknown' && observation.fingerprint !== null) {
        throw new SshHostsError(
          'HOST_KEY_UNKNOWN',
          `首次连接需要确认主机密钥：${host.alias}`,
          `服务器指纹 ${observation.fingerprint}；请用户核对后把该主机的 fingerprintPolicy 设为 accept-new 再连接`,
          error,
          observation.fingerprint,
        )
      }
      throw classify(error, 'connect')
    }

    if (observation.status === 'learned' && observation.fingerprint !== null) {
      try {
        await this.options.onFingerprint(host, observation.fingerprint)
      } catch (error) {
        client.end()
        throw new SshHostsError('FINGERPRINT_WRITE_FAILED', '无法保存首次连接的主机指纹', '请检查数据目录权限后重试', error, observation.fingerprint)
      }
    }

    let sftp: SFTPWrapper | null = null
    let home: string
    try {
      sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
        client.sftp((error, wrapper) => (error ? reject(error) : resolve(wrapper)))
      })
      home = await sftpRealpath(sftp, '.')
    } catch (error) {
      this.options.debug(`sftp unavailable on ${host.alias}, falling back to $HOME: ${error instanceof Error ? error.message : String(error)}`)
      sftp = null
      home = await this.homeViaExec(client, host.username).catch(() => (host.username === 'root' ? '/root' : `/home/${host.username}`))
    }
    const entry: ConnectionEntry = {
      key,
      host,
      client,
      fingerprint: observation.fingerprint ?? host.fingerprint?.sha256 ?? '',
      hostKeyStatus: observation.status === 'learned' ? 'learned' : 'matched',
      banner,
      home,
      lastUsed: Date.now(),
      active: 0,
      idleTimer: null,
      sftp,
      sftpPending: null,
      closed: false,
    }
    client.on('error', () => this.drop(host.id, entry))
    client.on('close', () => this.drop(host.id, entry))
    this.options.debug(`connected ${host.alias} (${host.username}@${host.host}:${host.port}) fingerprint=${entry.fingerprint}`)
    return entry
  }

  /** Resolve `$HOME` over an exec channel when the SFTP subsystem is absent. */
  private homeViaExec(client: SshClient, username: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      client.exec('printf %s "$HOME"', { pty: false }, (error, stream) => {
        if (error) {
          reject(error)
          return
        }
        let output = ''
        stream.on('data', (chunk: Buffer) => {
          output += chunk.toString('utf8')
        })
        stream.on('error', reject)
        stream.on('close', () => {
          const home = output.trim()
          resolve(home.startsWith('/') ? home : username === 'root' ? '/root' : `/home/${username}`)
        })
      })
    })
  }

  private async getSftp(entry: ConnectionEntry): Promise<SFTPWrapper> {
    if (entry.sftp !== null) return entry.sftp
    if (entry.sftpPending === null) {
      entry.sftpPending = new Promise<SFTPWrapper>((resolve, reject) => {
        entry.client.sftp((error, wrapper) => (error ? reject(error) : resolve(wrapper)))
      }).then((wrapper) => {
        entry.sftp = wrapper
        wrapper.on('close', () => {
          entry.sftp = null
        })
        return wrapper
      }).catch((error: unknown) => {
        entry.sftpPending = null
        throw new SshHostsError('SFTP_UNAVAILABLE', `服务器 ${entry.host.alias} 未启用 SFTP 子系统`, '请启用 SFTP，或改用 ssh_exec 在远端处理文件', error)
      })
    }
    return entry.sftpPending
  }

  private async verifyRealPath(
    sftp: SFTPWrapper,
    path: string,
    policy: RemotePathPolicy,
    requireDirectory = false,
    mode: 'read' | 'edit' = 'read',
  ): Promise<void> {
    let real: string
    try {
      real = await sftpRealpath(sftp, path)
    } catch (error) {
      const code = (error as { code?: unknown }).code
      if (code === 2) {
        throw new SshHostsError('REMOTE_NOT_FOUND', `远程路径不存在：${path}`, '请确认路径拼写，或先创建目录')
      }
      throw new SshHostsError('PATH_CHECK_FAILED', `无法解析远程路径：${path}`, '请检查该路径的权限与符号链接', error)
    }
    if (mode === 'edit') assertRemoteEditable(real, policy)
    else assertRemotePathAllowed(real, policy)
    const roots = mode === 'edit' ? policy.editablePaths : policy.allowedPaths
    const realRoots = await Promise.all(
      roots.map(async (entry) => {
        try {
          return await sftpRealpath(sftp, expandRemotePath(entry, policy.cwd, policy.home))
        } catch {
          return expandRemotePath(entry, policy.cwd, policy.home)
        }
      }),
    )
    if (!realRoots.some((root) => isRemoteInside(root, real))) {
      throw new SshHostsError(
        mode === 'edit' ? 'EDIT_PATH_DENIED' : 'REMOTE_PATH_DENIED',
        `远程路径经符号链接越界：${real}`,
        `只允许 ${realRoots.join('、')}`,
      )
    }
    if (requireDirectory) {
      const info = await sftpStat(sftp, real)
      if (!info.isDirectory()) throw new SshHostsError('NOT_DIRECTORY', `远程父路径不是目录：${real}`, '请指定有效的目录')
    }
  }

  /** Verify the deepest existing ancestor before creating directories under it. */
  private async verifyExistingAncestor(
    sftp: SFTPWrapper,
    target: string,
    policy: RemotePathPolicy,
    mode: 'read' | 'edit' = 'read',
  ): Promise<void> {
    let probe = target
    while (true) {
      const info = await sftpStat(sftp, probe).catch(() => undefined)
      if (info !== undefined) {
        await this.verifyRealPath(sftp, probe, policy, true, mode)
        return
      }
      const parent = posix.dirname(probe)
      if (parent === probe) return
      probe = parent
    }
  }

  private async mkdirp(sftp: SFTPWrapper, target: string): Promise<void> {
    const segments = posix.normalize(target).split('/').filter((segment) => segment.length > 0)
    let current = ''
    for (const segment of segments) {
      current += `/${segment}`
      try {
        const info = await sftpStat(sftp, current)
        if (!info.isDirectory()) throw new SshHostsError('NOT_DIRECTORY', `远程路径不是目录：${current}`, '请检查路径冲突')
      } catch (error) {
        if (error instanceof SshHostsError) throw error
        await sftpMkdir(sftp, current).catch((mkdirError: unknown) => {
          const code = (mkdirError as { code?: unknown }).code
          if (code !== 4) throw mkdirError
        })
      }
    }
  }

  private scheduleIdle(entry: ConnectionEntry): void {
    if (entry.idleTimer !== null) clearTimeout(entry.idleTimer)
    entry.idleTimer = setTimeout(() => {
      entry.idleTimer = null
      if (entry.active > 0 || entry.closed) {
        this.scheduleIdle(entry)
        return
      }
      if (Date.now() - entry.lastUsed < this.options.config.idleTimeoutMs) {
        this.scheduleIdle(entry)
        return
      }
      this.drop(entry.host.id, entry)
      void this.closeEntry(entry)
    }, this.options.config.idleTimeoutMs)
    entry.idleTimer.unref?.()
  }

  private drop(hostId: string, entry: ConnectionEntry): void {
    const current = this.pool.get(hostId)
    if (current === entry) this.pool.delete(hostId)
    entry.closed = true
    if (entry.idleTimer !== null) {
      clearTimeout(entry.idleTimer)
      entry.idleTimer = null
    }
    void this.closeEntry(entry)
  }

  private async closeEntry(entry: ConnectionEntry): Promise<void> {
    entry.closed = true
    if (entry.idleTimer !== null) {
      clearTimeout(entry.idleTimer)
      entry.idleTimer = null
    }
    entry.sftp = null
    try {
      entry.client.end()
    } catch {
      // Already closed.
    }
  }
}

function isConnectionLoss(error: unknown): boolean {
  if (error instanceof SshHostsError && (error.code === 'CONNECTION_LOST' || error.code === 'CONNECTION_REFUSED')) return true
  const code = (error as { code?: unknown }).code
  return code === 'ECONNRESET' || code === 'EPIPE' || code === 'NOT_CONNECTED'
}
