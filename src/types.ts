/** Shared domain types and the plugin's structured error. */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue }

export type AuthType = 'password' | 'key'
export type FingerprintPolicy = 'strict' | 'accept-new'
export type SecretsBackend = 'file' | 'env' | 'none'

/** How a privileged (`sudo`) command authenticates on one host. */
export type SudoMode = 'nopasswd' | 'password'

/**
 * Per-host privilege escalation policy. It is user-managed only: the
 * `ssh_host_add`/`ssh_host_update` tools never enable or widen it, and the
 * password itself lives in the encrypted credential store under
 * `host:<id>:sudo`.
 */
export interface HostSudo {
  mode: SudoMode
  /** Target account; `root` when omitted. */
  user?: string
  /** Credential-store key for the sudo password (password mode). */
  passwordRef?: string
}

export interface HostFingerprint {
  /** OpenSSH-style fingerprint, e.g. `SHA256:...`. */
  sha256: string
  /** ISO timestamp of the first observation. */
  addedAt: string
}

/** One service the server hosts, so the Agent knows where work happens. */
export interface HostService {
  /** Stable short name, e.g. api, worker, db. */
  name: string
  /** Directory the service lives in: absolute or `~/...`. */
  directory: string
  /** What the service does, and anything the Agent must know before touching it. */
  description?: string
  /** How to restart/start it, e.g. `systemctl restart api` or `docker compose up -d`. */
  startCommand?: string
  /** Log location, e.g. `~/app/logs/app.log` or `/var/log/nginx/error.log`. */
  logPath?: string
  /** Local listening port, when useful. */
  port?: number
}

export interface PasswordAuth {
  type: 'password'
  /** Key in the encrypted credential store; never a secret value. */
  secretRef: string
}

export interface KeyAuth {
  type: 'key'
  /** Local path to the private key. It is read, used, and never copied. */
  privateKeyPath: string
  /** Key in the encrypted credential store for an encrypted key. */
  passphraseRef?: string
}

export type HostAuth = PasswordAuth | KeyAuth

export interface HostRecord {
  id: string
  alias: string
  host: string
  port: number
  username: string
  auth: HostAuth
  /** TOFU result; null until the first successful connection. */
  fingerprint: HostFingerprint | null
  fingerprintPolicy: FingerprintPolicy
  defaultCwd?: string
  /** Remote roots this server may touch. `~` expands to the login home. */
  allowedPaths: string[]
  /** Remote roots this server may edit/upload to; empty means no edits. */
  editablePaths: string[]
  /** Declared services and the directories they live in. */
  services: HostService[]
  /** Privileged execution policy; absent means sudo is not configured. */
  sudo?: HostSudo
  /** Remote paths that are always refused. */
  deniedPaths: string[]
  readOnly: boolean
  tags: string[]
  note?: string
  createdAt: string
  updatedAt: string
}

/** Redacted view of one host's privilege escalation policy. */
export interface SudoView {
  mode: 'off' | SudoMode
  user: string | null
  /** Whether a sudo password is stored (always false in off/nopasswd mode). */
  passwordConfigured: boolean
}

/** What the model is allowed to see about a host. */
export interface HostView {
  id: string
  alias: string
  host: string
  port: number
  username: string
  authType: AuthType
  hasFingerprint: boolean
  fingerprint: string | null
  fingerprintPolicy: FingerprintPolicy
  credentialStatus: 'available' | 'missing' | 'unavailable'
  privateKeyConfigured: boolean
  defaultCwd: string | null
  allowedPaths: string[]
  editablePaths: string[]
  /**
   * Scratch directory granted read+write on top of the stored lists (`/tmp` by
   * default); null when the deployment disabled `tempDir`.
   */
  tempDir: string | null
  services: HostService[]
  /** Privilege escalation policy (never contains the password). */
  sudo: SudoView
  deniedPaths: string[]
  readOnly: boolean
  tags: string[]
  note: string | null
  createdAt: string
  updatedAt: string
}

export interface ExecResult {
  server: string
  command: string
  cwd: string
  exitCode: number | null
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
  truncated: boolean
  originalBytes: number
  approval: 'not-required' | 'granted' | 'policy-allow' | 'full-access'
  /** Whether the command ran through the host's configured sudo. */
  privileged: boolean
  /** Which sudo mode ran it; null for unprivileged commands. */
  privilegeMode: SudoMode | null
}

export interface SftpReadResult {
  path: string
  content: string
  bytes: number
  originalBytes: number
  truncated: boolean
}

export interface SftpWriteResult {
  path: string
  bytesWritten: number
  created: boolean
  overwritten: boolean
}

export interface TransferResult {
  direction: 'upload' | 'download'
  localPath: string
  remotePath: string
  server: string
  bytes: number
  overwritten: boolean
}

export interface TestResult {
  server: string
  reachable: boolean
  authOk: boolean
  hostKeyFingerprint: string | null
  hostKeyStatus: 'matched' | 'learned' | 'changed' | 'unknown' | 'not-checked'
  banner: string | null
  homeDir: string | null
  durationMs: number
  error: {
    code: string
    message: string
    hint: string | null
  } | null
}

/** An error that carries a stable machine code and an actionable hint. */
export class SshHostsError extends Error {
  readonly code: string
  readonly hint: string | null
  /** Host-key fingerprint observed at failure time, when one was seen. */
  readonly fingerprint: string | null

  constructor(code: string, message: string, hint?: string, cause?: unknown, fingerprint?: string | null) {
    super(`${message} [${code}]`, cause === undefined ? undefined : { cause })
    this.name = 'SshHostsError'
    this.code = code
    this.hint = hint ?? null
    this.fingerprint = fingerprint ?? null
  }
}

/** Render one error as a single model-facing line, keeping the hint. */
export function describeError(error: unknown): string {
  if (error instanceof SshHostsError) {
    return error.hint ? `${error.message}（${error.hint}）` : error.message
  }
  if (error instanceof Error) return error.message
  return String(error)
}
