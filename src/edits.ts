/**
 * Best-effort detection of shell commands that write files. A shell cannot be
 * confined without OS-level permissions; this guard makes the common forms
 * (`>`, tee, sed -i, cp/mv/rm/touch, package managers) honor editablePaths.
 */

import { expandRemotePath, extractPathTokens, isRemoteInside, tempDirHint, type RemotePathPolicy } from './paths.js'
import { SshHostsError } from './types.js'

const EDIT_RULES: Array<{ id: string; pattern: RegExp }> = [
  { id: 'redirect', pattern: /(?:^|[^0-9])>{1,2}(?![>&])/ },
  { id: 'tee', pattern: /\btee\b/ },
  { id: 'sed-in-place', pattern: /\bsed\s+(?:-[A-Za-z]*i|--in-place)\b/ },
  { id: 'perl-in-place', pattern: /\bperl\s+-[A-Za-z]*i\b/ },
  { id: 'copy', pattern: /\b(?:cp|install)\b/ },
  { id: 'move', pattern: /\bmv\b/ },
  { id: 'remove', pattern: /\b(?:rm|rmdir|unlink)\b/ },
  { id: 'create', pattern: /\b(?:touch|mkdir)\b/ },
  { id: 'attrs', pattern: /\b(?:chmod|chown|chattr|setfacl)\b/ },
  { id: 'truncate', pattern: /\b(?:truncate|dd)\b/ },
  { id: 'rsync', pattern: /\brsync\b/ },
  { id: 'git-write', pattern: /\bgit\s+(?:checkout|reset|clean|apply|restore)\b/ },
  { id: 'package-install', pattern: /\b(?:npm|pnpm|yarn)\s+(?:install|ci|add|remove|uninstall)\b/ },
  { id: 'pip-install', pattern: /\b(?:pip|pip3)\s+install\b/ },
  { id: 'system-package', pattern: /\b(?:apt|apt-get|yum|dnf|zypper)\s+(?:install|remove|purge|upgrade|update)\b/ },
  { id: 'archive', pattern: /\b(?:unzip|tar\s+[^\n]*\s-[A-Za-z]*x)\b/ },
  { id: 'container', pattern: /\b(?:docker|podman)\s+(?:cp|rm|build|pull|run)\b/ },
  { id: 'kubectl', pattern: /\bkubectl\s+(?:apply|delete|cp|exec)\b/ },
]

const DEVICE_TARGETS = ['/dev/null', '/dev/stdin', '/dev/stdout', '/dev/stderr']

/** Remove redirections to /dev/null before deciding whether a command edits. */
function withoutNullRedirects(command: string): string {
  return command.replace(/[0-9]*>{1,2}\s*\/dev\/(?:null|stdin|stdout|stderr)/g, ' ')
}

/** Whether the command appears to write to the remote filesystem. */
export function detectCommandEdit(command: string): { edits: boolean; matched: string[] } {
  const source = withoutNullRedirects(command.replace(/'[^']*'/g, "''").replace(/"[^"]*"/g, '""'))
  const matched = EDIT_RULES.filter((rule) => rule.pattern.test(source)).map((rule) => rule.id)
  return { edits: matched.length > 0, matched }
}

/**
 * Refuse an edit-like command unless its cwd and every path-like argument are
 * inside the host's editablePaths. Disable with `guardCommandEdits: false`.
 */
export function assertCommandEditsAllowed(command: string, policy: RemotePathPolicy): void {
  const intent = detectCommandEdit(command)
  if (!intent.edits) return
  const roots = policy.editablePaths.map((entry) => expandRemotePath(entry, policy.cwd, policy.home))
  const scratch = tempDirHint(policy)
  if (roots.length === 0) {
    throw new SshHostsError(
      'EDIT_PATH_DENIED',
      `服务器未配置 editablePaths，不能执行会写文件的命令（${intent.matched.join('、')}）`,
      scratch === null
        ? '请由用户编辑 hosts.json 配置可编辑目录；读取/下载仍可用 ssh_read_file、ssh_download'
        : `${scratch}；需要长期写入的目录请由用户编辑 hosts.json 的 editablePaths`,
    )
  }
  if (!roots.some((root) => isRemoteInside(root, policy.cwd))) {
    throw new SshHostsError(
      'EDIT_PATH_DENIED',
      `会写文件的命令必须在 editablePaths 内执行，当前 cwd=${policy.cwd}`,
      `可编辑目录：${roots.join('、')}；请把 cwd 改到这些目录${scratch === null ? '' : `，临时文件的命令用 cwd=${policy.tempDir}`}`,
    )
  }
  for (const token of extractPathTokens(command)) {
    if (DEVICE_TARGETS.some((device) => token === device || token.startsWith(`${device}/`))) continue
    let resolved: string
    try {
      resolved = expandRemotePath(token, policy.cwd, policy.home)
    } catch {
      continue
    }
    if (!roots.some((root) => isRemoteInside(root, resolved))) {
      throw new SshHostsError(
        'EDIT_PATH_DENIED',
        `命令试图写到可编辑目录之外：${token}`,
        scratch === null
          ? `只允许 ${roots.join('、')}；请改用 ssh_write_file/ssh_upload，或由用户调整 editablePaths`
          : `只允许 ${roots.join('、')}；${scratch}，或改用 ssh_write_file/ssh_upload`,
      )
    }
  }
}
