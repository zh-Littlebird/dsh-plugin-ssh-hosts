/** Deployment configuration, defaults, and the resolved data directory. */

import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import z from '@deepseek-ai/schemastery'
import type { SecretsBackend } from './types.js'

export type HighRiskPolicy = 'ask' | 'deny' | 'allow'

/**
 * How the first `ssh_*` call for a target is admitted.
 *
 * `ask` (the default) asks the user through the approval seam exactly once per
 * session and per target (one server, or one inventory scope), then remembers
 * the grant in this process. `allow` restores the old unconditional behaviour,
 * and `deny` blocks every tool call. A process restart clears the in-memory
 * grants, so a resumed session is asked again.
 */
export type SessionConsentPolicy = 'ask' | 'allow' | 'deny'

export interface SshHostsConfig {
  /** Directory for hosts.json, credentials, known keys, transfers, and audit.log. */
  dataDir: string
  /** Per-stream output cap before head/tail truncation. */
  maxOutputBytes: number
  /** Default command timeout. */
  timeoutMs: number
  /** Upper bound a model may request per call. */
  maxTimeoutMs: number
  /** TCP/SSH handshake timeout. */
  connectTimeoutMs: number
  /** Close an unused connection after this period. */
  idleTimeoutMs: number
  /** Concurrent operations allowed on one server. */
  maxConcurrentPerHost: number
  /** Largest file read, upload, or download. */
  maxTransferBytes: number
  /** Where passwords and key passphrases come from. */
  secretsBackend: SecretsBackend
  /** Prefix for environment-backed secrets. */
  envPrefix: string
  /** What to do with a command classified as high risk. */
  highRiskPolicy: HighRiskPolicy
  /** Whether the first `ssh_*` call for a server (or inventory scope) asks the user. */
  sessionConsent: SessionConsentPolicy
  /**
   * Trust a session whose approval prompts are disabled (“完全权限”):
   * treat the SSH authorization and high-risk commands as already granted
   * instead of failing closed on a prompt that can never be shown.
   */
  trustFullAccess: boolean
  /** Append one JSON line per operation. */
  audit: boolean
  /** Verbose, redacted diagnostics on stderr. */
  debug: boolean
  /** Extra local roots that upload/download may read or write. */
  localRoots: string[]
  /** Refuse absolute path arguments in commands that leave the allowed roots. */
  strictCommandPaths: boolean
  /** Refuse edit-like shell commands outside editablePaths. */
  guardCommandEdits: boolean
  /**
   * Remote scratch directory granted read+write on every host (default `/tmp`).
   * It is folded into the effective `allowedPaths`/`editablePaths`, so the
   * model can keep process files there instead of scattering them across
   * service directories. An empty string disables the grant.
   */
  tempDir: string
}

const DEFAULTS: SshHostsConfig = {
  dataDir: '',
  maxOutputBytes: 128 * 1024,
  timeoutMs: 60_000,
  maxTimeoutMs: 300_000,
  connectTimeoutMs: 20_000,
  idleTimeoutMs: 5 * 60_000,
  maxConcurrentPerHost: 8,
  maxTransferBytes: 50 * 1024 * 1024,
  secretsBackend: 'file',
  envPrefix: 'SSH_HOST_',
  highRiskPolicy: 'ask',
  sessionConsent: 'ask',
  trustFullAccess: true,
  audit: true,
  debug: false,
  localRoots: [],
  strictCommandPaths: false,
  guardCommandEdits: true,
  tempDir: '/tmp',
}

export const Config = z.object({
  dataDir: z.string().default('').description('数据目录；留空使用 $DSH_HOME/ssh-hosts。'),
  maxOutputBytes: z.number().default(DEFAULTS.maxOutputBytes).description('单条命令 stdout/stderr 各自的最大保留字节数。'),
  timeoutMs: z.number().default(DEFAULTS.timeoutMs).description('命令默认超时（毫秒）。'),
  maxTimeoutMs: z.number().default(DEFAULTS.maxTimeoutMs).description('模型可请求的最大超时（毫秒）。'),
  connectTimeoutMs: z.number().default(DEFAULTS.connectTimeoutMs).description('SSH 连接与握手超时（毫秒）。'),
  idleTimeoutMs: z.number().default(DEFAULTS.idleTimeoutMs).description('空闲连接关闭时间（毫秒）。'),
  maxConcurrentPerHost: z.number().default(DEFAULTS.maxConcurrentPerHost).description('单台服务器并发操作上限。'),
  maxTransferBytes: z.number().default(DEFAULTS.maxTransferBytes).description('单次文件读写/上传/下载大小上限（字节）。'),
  secretsBackend: z.string().default(DEFAULTS.secretsBackend).description('凭据后端：file、env 或 none。'),
  envPrefix: z.string().default(DEFAULTS.envPrefix).description('env 后端的环境变量前缀。'),
  highRiskPolicy: z.string().default(DEFAULTS.highRiskPolicy).description('高风险命令策略：ask、deny 或 allow。'),
  sessionConsent: z.string().default(DEFAULTS.sessionConsent).description('本会话首次调用 SSH 工具时是否向用户申请授权：ask（默认）、allow 或 deny。'),
  trustFullAccess: z
    .boolean()
    .default(DEFAULTS.trustFullAccess)
    .description('会话处于完全权限（审批策略为 never 且文件策略为 danger-full-access）时，是否直接放行 SSH 授权与高风险命令；关闭后按失败关闭处理。'),
  audit: z.boolean().default(DEFAULTS.audit).description('是否写入 audit.log。'),
  debug: z.boolean().default(DEFAULTS.debug).description('是否输出脱敏调试日志。'),
  localRoots: z.array(z.string()).default([]).description('上传/下载允许访问的额外本地根目录。'),
  strictCommandPaths: z.boolean().default(DEFAULTS.strictCommandPaths).description('是否拒绝命令中越出 allowedPaths 的绝对路径参数。'),
  guardCommandEdits: z.boolean().default(DEFAULTS.guardCommandEdits).description('是否拒绝在 editablePaths 之外执行明显会写文件的 shell 命令。'),
  tempDir: z
    .string()
    .default(DEFAULTS.tempDir)
    .description('每台服务器默认获得读写权限的远程临时目录（默认 /tmp），用于存放过程中的临时文件；填空字符串关闭该授权。主机的 deniedPaths 仍然优先。'),
})

function positive(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback
}

/** Fill omissions so `apply` behaves the same when called without the Loader. */
export function withDefaults(config: Partial<SshHostsConfig> | undefined): SshHostsConfig {
  const input = config ?? {}
  const secretsBackend = input.secretsBackend
  const highRiskPolicy = input.highRiskPolicy
  const sessionConsent = input.sessionConsent
  return {
    dataDir: typeof input.dataDir === 'string' ? input.dataDir : DEFAULTS.dataDir,
    maxOutputBytes: positive(input.maxOutputBytes, DEFAULTS.maxOutputBytes),
    timeoutMs: positive(input.timeoutMs, DEFAULTS.timeoutMs),
    maxTimeoutMs: positive(input.maxTimeoutMs, DEFAULTS.maxTimeoutMs),
    connectTimeoutMs: positive(input.connectTimeoutMs, DEFAULTS.connectTimeoutMs),
    idleTimeoutMs: positive(input.idleTimeoutMs, DEFAULTS.idleTimeoutMs),
    maxConcurrentPerHost: positive(input.maxConcurrentPerHost, DEFAULTS.maxConcurrentPerHost),
    maxTransferBytes: positive(input.maxTransferBytes, DEFAULTS.maxTransferBytes),
    secretsBackend:
      secretsBackend === 'env' || secretsBackend === 'none' || secretsBackend === 'file'
        ? secretsBackend
        : DEFAULTS.secretsBackend,
    envPrefix: typeof input.envPrefix === 'string' && input.envPrefix.length > 0 ? input.envPrefix : DEFAULTS.envPrefix,
    highRiskPolicy:
      highRiskPolicy === 'deny' || highRiskPolicy === 'allow' || highRiskPolicy === 'ask'
        ? highRiskPolicy
        : DEFAULTS.highRiskPolicy,
    sessionConsent:
      sessionConsent === 'allow' || sessionConsent === 'deny' || sessionConsent === 'ask'
        ? sessionConsent
        : DEFAULTS.sessionConsent,
    trustFullAccess: typeof input.trustFullAccess === 'boolean' ? input.trustFullAccess : DEFAULTS.trustFullAccess,
    audit: typeof input.audit === 'boolean' ? input.audit : DEFAULTS.audit,
    debug: typeof input.debug === 'boolean' ? input.debug : DEFAULTS.debug,
    localRoots: Array.isArray(input.localRoots) ? input.localRoots.filter((entry): entry is string => typeof entry === 'string') : [],
    strictCommandPaths:
      typeof input.strictCommandPaths === 'boolean' ? input.strictCommandPaths : DEFAULTS.strictCommandPaths,
    guardCommandEdits:
      typeof input.guardCommandEdits === 'boolean' ? input.guardCommandEdits : DEFAULTS.guardCommandEdits,
    tempDir: typeof input.tempDir === 'string' ? input.tempDir.trim() : DEFAULTS.tempDir,
  }
}

/** `$DSH_HOME/ssh-hosts`, or the same path under the user's home when unset. */
export function resolveDataDir(config: SshHostsConfig): string {
  const override = process.env.DSH_SSH_HOSTS_DATA_DIR
  if (override !== undefined && override.trim().length > 0) return resolve(override)
  if (config.dataDir.length > 0) return resolve(config.dataDir)
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  return resolve(home, 'ssh-hosts')
}

/**
 * The configured scratch directory as shown to humans and the model, or null
 * when the grant is disabled. `~/…` stays literal here because the login home
 * is only known after connecting; {@link resolveTempRoot} expands it for the
 * actual path checks.
 */
export function configuredTempDir(config: SshHostsConfig): string | null {
  const raw = config.tempDir.trim()
  return raw.length === 0 ? null : raw
}
