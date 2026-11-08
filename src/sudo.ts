/**
 * Privilege escalation (`sudo`) support for `ssh_exec`.
 *
 * Two things happen here:
 *
 * 1. A command that literally starts with `sudo …` is recognised and rewritten
 *    so it runs through the plugin's own wrapper (which knows how to supply a
 *    password); `privileged: true` expresses the same intent without typing
 *    `sudo`. sudo flags the plugin cannot reproduce (`-i`, `-s`, `-e`, …) are
 *    reported instead of being silently dropped.
 * 2. The per-host sudo policy is resolved into one {@link ExecPrivilege}: which
 *    mode, which target user, and—for password mode only—the password, which
 *    never leaves this process and is only ever written to the SSH channel's
 *    stdin.
 */

import type { ToolDeps } from './deps.js'
import { registerSecret } from './redact.js'
import type { SecretStore } from './secrets.js'
import type { ExecPrivilege } from './ssh.js'
import type { HostRecord, HostSudo } from './types.js'
import { SshHostsError } from './types.js'

/** Default credential-store key for a host's sudo password. */
export function sudoPasswordRef(hostId: string): string {
  return `host:${hostId}:sudo`
}

/** Where this host's sudo password lives, following the stored reference. */
export function sudoSecretRef(host: HostRecord): string | undefined {
  if (host.sudo?.mode !== 'password') return undefined
  return host.sudo.passwordRef ?? sudoPasswordRef(host.id)
}

/**
 * Whether a usable sudo password exists, without ever reading its value.
 * The login password counts when the host authenticates with a password,
 * because {@link resolveSudoPassword} falls back to it.
 */
export async function sudoPasswordStatus(
  options: { secrets: Pick<SecretStore, 'status'> },
  host: HostRecord,
): Promise<'available' | 'missing' | 'unavailable'> {
  const ref = sudoSecretRef(host)
  if (ref === undefined) return 'unavailable'
  const own = await options.secrets.status(ref)
  if (own === 'available') return 'available'
  if (host.auth.type === 'password') return options.secrets.status(host.auth.secretRef)
  return own
}

/** Conservative POSIX account-name shape for `sudo -u`. */
export const SUDO_USER_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$/

/** sudo flags that only affect prompting, so re-applying them is unnecessary. */
const IGNORED_FLAGS = new Set([
  '--',
  '-n',
  '--non-interactive',
  '-E',
  '--preserve-env',
  '-H',
  '--set-home',
  '-S',
  '--stdin',
  '-k',
  '--reset-timestamp',
  '-A',
  '--askpass',
  '-P',
  '--preserve-groups',
])

export interface SudoPrefix {
  /** Whether the command starts with the `sudo` word. */
  privileged: boolean
  /** The command with the leading `sudo` and its option tokens removed. */
  command: string
  /** Target user requested with `-u/--user`. */
  user?: string
  /** sudo flags this plugin cannot reproduce; callers must reject them. */
  unsupported: string[]
}

function tokenAt(text: string, from: number): { token: string; start: number; end: number } | undefined {
  const space = /^\s+/.exec(text.slice(from))
  if (space === null) return undefined
  const start = from + space[0].length
  const token = /^\S+/.exec(text.slice(start))
  if (token === null) return undefined
  return { token: token[0], start, end: start + token[0].length }
}

/**
 * Split a leading `sudo` invocation from the command it runs.
 *
 * The remaining command text is preserved byte for byte (only the leading
 * whitespace is trimmed), so quoting and `&&` chains survive untouched.
 */
export function parseSudoPrefix(command: string): SudoPrefix {
  const head = /^\s*sudo(?=\s|$)/.exec(command)
  if (head === null) return { privileged: false, command, unsupported: [] }
  let position = head[0].length
  let user: string | undefined
  const unsupported: string[] = []
  for (;;) {
    const next = tokenAt(command, position)
    if (next === undefined) break
    const token = next.token
    if (!token.startsWith('-')) break
    if (token === '-u' || token === '--user') {
      const value = tokenAt(command, next.end)
      if (value === undefined) {
        unsupported.push(token)
        break
      }
      user = value.token
      position = value.end
      continue
    }
    if (token.startsWith('--user=')) {
      user = token.slice('--user='.length)
      position = next.end
      continue
    }
    if (token.startsWith('-u') && !token.startsWith('--') && token.length > 2) {
      user = token.slice(2)
      position = next.end
      continue
    }
    if (IGNORED_FLAGS.has(token)) {
      position = next.end
      continue
    }
    // `-i`, `-s`, `-e`, `-g`, `-l`, … change what sudo executes; refusing is
    // safer than quietly running something different.
    unsupported.push(token)
    position = next.end
  }
  return { privileged: true, command: command.slice(position).trim(), user, unsupported }
}

function validateSudoUser(user: string): string {
  if (!SUDO_USER_PATTERN.test(user)) {
    throw new SshHostsError('INVALID_SUDO', `sudo 目标用户无效：${user}`, '用户名只能包含字母、数字、下划线、点和连字符')
  }
  return user
}

async function resolveSudoPassword(deps: ToolDeps, host: HostRecord, sudo: HostSudo): Promise<string> {
  const ref = sudo.passwordRef ?? sudoPasswordRef(host.id)
  const stored = await deps.secrets.get(ref)
  if (stored !== undefined && stored.length > 0) return stored
  // Convenience: on a password-authenticated host the login password is
  // usually the sudo password too. It is still never shown to the model.
  if (host.auth.type === 'password') {
    const login = await deps.secrets.get(host.auth.secretRef)
    if (login !== undefined && login.length > 0) {
      registerSecret(login)
      return login
    }
  }
  throw new SshHostsError(
    'SUDO_PASSWORD_MISSING',
    `服务器 ${host.alias} 的 sudo 配置为密码模式，但没有可用的 sudo 密码`,
    `请由用户在本机运行 scripts/dsh-ssh.mjs set ${host.alias} --sudo 录入 sudo 密码（或在 Web「SSH 服务器」页面填写），或把该主机的 sudo 模式改为 nopasswd；模型不会接收密码`,
  )
}

/**
 * Resolve the effective privilege for one call.
 *
 * Returns `undefined` for an unprivileged command. Throws when the command
 * asked for root but the host has no usable sudo configuration, so the model
 * gets an actionable error instead of a confusing shell failure.
 */
export async function resolvePrivilege(
  deps: ToolDeps,
  host: HostRecord,
  request: { privileged: boolean; user?: string },
): Promise<ExecPrivilege | undefined> {
  if (!request.privileged) return undefined
  const sudo = host.sudo
  if (sudo === undefined) {
    throw new SshHostsError(
      'SUDO_NOT_CONFIGURED',
      `服务器 ${host.alias} 尚未配置 sudo，无法执行提权命令`,
      '请由用户在该主机的 hosts.json 或 Web「SSH 服务器」页面启用 sudo：推荐在服务器上配置 NOPASSWD（mode=nopasswd），或填写 sudo 密码（mode=password）',
    )
  }
  if (request.user !== undefined) validateSudoUser(request.user)
  if (sudo.user !== undefined && request.user !== undefined && sudo.user !== request.user) {
    throw new SshHostsError(
      'SUDO_USER_LOCKED',
      `命令请求以 ${request.user} 身份执行，但该主机固定为 ${sudo.user}`,
      `请改用 privileged: true（默认使用 ${sudo.user}），或由用户在 hosts.json 中调整 sudo.user`,
    )
  }
  const user = request.user ?? sudo.user
  let password: string | undefined
  if (sudo.mode === 'password') {
    password = await resolveSudoPassword(deps, host, sudo)
    registerSecret(password)
  }
  return {
    mode: sudo.mode,
    ...(user === undefined ? {} : { user }),
    ...(password === undefined ? {} : { password }),
  }
}
