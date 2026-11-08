/** POSIX remote-path resolution, allowlists, and shell quoting. */

import { posix } from 'node:path'
import { SshHostsError } from './types.js'

export interface RemotePathPolicy {
  home: string
  cwd: string
  allowedPaths: string[]
  editablePaths: string[]
  deniedPaths: string[]
  /**
   * Effective scratch directory (already expanded to an absolute path), or
   * null/absent when the `tempDir` grant is disabled. It is informational:
   * it is already folded into {@link allowedPaths} and {@link editablePaths};
   * the messages use it to tell the model where its process files belong.
   */
  tempDir?: string | null
}

/** Expand `~`, anchor relative paths at `cwd`, and normalize to absolute POSIX form. */
export function expandRemotePath(input: string, cwd: string, home: string): string {
  const trimmed = input.trim()
  if (trimmed.length === 0) throw new SshHostsError('INVALID_PATH', '远程路径不能为空', '请提供绝对路径、~/ 路径或相对当前目录的路径')
  if (trimmed.includes('\0')) throw new SshHostsError('INVALID_PATH', '远程路径包含空字节', '请提供合法路径')
  if (/[\r\n]/.test(trimmed)) throw new SshHostsError('INVALID_PATH', '远程路径包含换行符', '请提供单行路径')
  let anchored: string
  if (trimmed === '~') anchored = home
  else if (trimmed.startsWith('~/')) anchored = posix.join(home, trimmed.slice(2))
  else if (trimmed.startsWith('/')) anchored = trimmed
  else anchored = posix.join(cwd, trimmed)
  const normalized = posix.normalize(anchored)
  return normalized.length > 1 && normalized.endsWith('/') ? normalized.slice(0, -1) : normalized
}

/** Whether `target` is `root` or lives below it. */
export function isRemoteInside(root: string, target: string): boolean {
  if (root === '/') return target.startsWith('/')
  return target === root || target.startsWith(`${root}/`)
}

/**
 * Expand the configured scratch directory (`tempDir`) against the login home.
 * Returns null for an empty value, which means the grant is disabled.
 */
export function resolveTempRoot(tempDir: string | null | undefined, home: string): string | null {
  const raw = (tempDir ?? '').trim()
  if (raw.length === 0) return null
  try {
    return expandRemotePath(raw, home, home)
  } catch {
    return null
  }
}

/**
 * Fold the scratch directory into one path list unless a root already covers
 * it (for example `~` or `/`). Returns a copy; the stored host policy is never
 * mutated.
 */
export function withTempRoot(roots: string[], tempRoot: string | null, home: string, cwd: string): string[] {
  if (tempRoot === null || tempRoot.length === 0) return [...roots]
  const expanded = roots.map((root) => expandRemotePath(root, cwd, home))
  if (expanded.some((root) => isRemoteInside(root, tempRoot))) return [...roots]
  return [...roots, tempRoot]
}

/**
 * The scratch grant that actually applies to one host: `deniedPaths` wins, so
 * a host that denies `/tmp` does not get it folded into its policy and the
 * instructions never point the model at a refused directory.
 */
export function effectiveTempRoot(
  tempRoot: string | null,
  deniedPaths: string[],
  home: string,
  cwd: string,
): string | null {
  if (tempRoot === null || tempRoot.length === 0) return null
  if (deniedPaths.some((denied) => matchesDenied(tempRoot, denied, home, cwd))) return null
  return tempRoot
}

/** Redirect scratch files to the shared temp directory, when one is granted. */
export function tempDirHint(policy: RemotePathPolicy): string | null {
  const tempDir = policy.tempDir
  if (tempDir === undefined || tempDir === null || tempDir.length === 0) return null
  return `过程的临时文件请写到 ${tempDir}（默认已授权读写）并在用完后删除`
}

function matchesDenied(target: string, denied: string, home: string, cwd: string): boolean {
  const expanded = expandRemotePath(denied, cwd, home)
  if (expanded.endsWith('*')) {
    const prefix = expanded.slice(0, -1)
    return target.startsWith(prefix)
  }
  return isRemoteInside(expanded, target)
}

/** Refuse a path outside every allowed root or inside a denied root. */
export function assertRemotePathAllowed(target: string, policy: RemotePathPolicy): string {
  for (const denied of policy.deniedPaths) {
    if (matchesDenied(target, denied, policy.home, policy.cwd)) {
      throw new SshHostsError('REMOTE_PATH_DENIED', `远程路径被禁止访问：${target}`, '该路径在服务器的 deniedPaths 中，请换一个路径或由用户调整配置')
    }
  }
  const allowed = policy.allowedPaths.map((entry) => expandRemotePath(entry, policy.cwd, policy.home))
  if (!allowed.some((root) => isRemoteInside(root, target))) {
    throw new SshHostsError(
      'REMOTE_PATH_DENIED',
      `远程路径越界：${target}`,
      `只允许访问 ${allowed.join('、')}；如需扩展请由用户修改该服务器的 allowedPaths`,
    )
  }
  return target
}

/** Resolve a user path and enforce the server policy in one step. */
export function resolveRemotePath(input: string, policy: RemotePathPolicy): string {
  return assertRemotePathAllowed(expandRemotePath(input, policy.cwd, policy.home), policy)
}

/** Refuse a write target outside every editable root. */
export function assertRemoteEditable(target: string, policy: RemotePathPolicy): string {
  assertRemotePathAllowed(target, policy)
  const editable = policy.editablePaths.map((entry) => expandRemotePath(entry, policy.cwd, policy.home))
  const scratch = tempDirHint(policy)
  if (editable.length === 0) {
    throw new SshHostsError(
      'EDIT_PATH_DENIED',
      `服务器未配置 editablePaths，禁止写入：${target}`,
      scratch === null
        ? '请由用户编辑 hosts.json 设置可编辑目录；读取/下载仍可用'
        : `${scratch}；需要长期写入的目录请由用户编辑 hosts.json 的 editablePaths`,
    )
  }
  if (!editable.some((root) => isRemoteInside(root, target))) {
    throw new SshHostsError(
      'EDIT_PATH_DENIED',
      `路径不在可编辑目录内：${target}`,
      scratch === null
        ? `只允许 ${editable.join('、')}；请由用户调整 editablePaths`
        : `只允许 ${editable.join('、')}；${scratch}，或在确有需要时由用户调整 editablePaths`,
    )
  }
  return target
}

/** The effective working directory, defaulting to the login home. */
export function resolveRemoteCwd(input: string | undefined, policy: Omit<RemotePathPolicy, 'cwd'>): string {
  if (input === undefined || input.trim().length === 0) return policy.home
  return assertRemotePathAllowed(expandRemotePath(input, policy.home, policy.home), { ...policy, cwd: policy.home })
}

/** Quote one string for a POSIX shell. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

/** Run a command in a directory without changing its exit status semantics. */
export function wrapCommand(command: string, cwd: string): string {
  if (cwd.length === 0) return command
  return `cd -- ${shellQuote(cwd)} && ${command}`
}

/**
 * Extract path-like shell tokens. This is a conservative scanner, not a shell
 * parser: it handles quoting and redirections well enough to enforce a denylist
 * and an optional allowlist, and it never rewrites the command.
 */
export function extractPathTokens(command: string): string[] {
  const tokens: string[] = []
  const matcher = /(?:[^\s'"]+|'[^']*'|"[^"]*")+/g
  let match: RegExpExecArray | null
  while ((match = matcher.exec(command)) !== null) {
    let token = match[0].trim()
    token = token.replace(/^[0-9]*[<>]+/, '')
    token = token.replace(/[;|&]+$/, '')
    token = token.replace(/^[("'`]+|[)"'`,]+$/g, '')
    if (token.includes('=')) token = token.slice(token.indexOf('=') + 1).replace(/^["']|["']$/g, '')
    if (token.includes('://')) continue
    if (token.startsWith('/') || token === '~' || token.startsWith('~/') || token.startsWith('.') || token.includes('/')) {
      tokens.push(token)
    }
  }
  return tokens
}

/** Always refuse command arguments that name a denied path. */
export function assertCommandPathsAllowed(command: string, policy: RemotePathPolicy, strict: boolean): void {
  for (const token of extractPathTokens(command)) {
    let resolved: string
    try {
      resolved = expandRemotePath(token, policy.cwd, policy.home)
    } catch {
      continue
    }
    for (const denied of policy.deniedPaths) {
      if (matchesDenied(resolved, denied, policy.home, policy.cwd)) {
        throw new SshHostsError(
          'COMMAND_PATH_DENIED',
          `命令包含被禁止的路径：${token}`,
          '请移除该路径，或由用户调整该服务器的 deniedPaths',
        )
      }
    }
    if (!strict) continue
    const allowed = policy.allowedPaths.map((entry) => expandRemotePath(entry, policy.cwd, policy.home))
    if (!allowed.some((root) => isRemoteInside(root, resolved))) {
      throw new SshHostsError(
        'COMMAND_PATH_DENIED',
        `命令包含越界路径：${token}`,
        `strictCommandPaths 已开启，只允许 ${allowed.join('、')}`,
      )
    }
  }
}
