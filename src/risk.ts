/**
 * Command risk classification for human approval. This is a guardrail, not a
 * shell sandbox: an obfuscated command can evade pattern matching, which is why
 * the server allowlist, path allowlist, and audit log exist independently.
 */

export interface RiskAssessment {
  high: boolean
  reasons: string[]
  matched: string[]
}

interface RiskRule {
  id: string
  pattern: RegExp
  reason: string
  /** Match the raw command instead of the quote-stripped form. */
  raw?: boolean
}

const RULES: RiskRule[] = [
  { id: 'rm-recursive', pattern: /\brm\s+(?:-[A-Za-z]*[rR][A-Za-z]*[fF]?[A-Za-z]*|[A-Za-z]*[fF][A-Za-z]*[rR][A-Za-z]*)(?:\s|$)/, reason: '递归删除文件' },
  { id: 'rm-root', pattern: /\brm\s+[^\n]*\s\/(?:\s|$|\*)/, reason: '删除根目录内容' },
  { id: 'mkfs', pattern: /\bmkfs(?:\.[A-Za-z0-9]+)?\b/, reason: '格式化文件系统' },
  { id: 'dd-device', pattern: /\bdd\b[^\n]*\bof=\/dev\//, reason: '直接写入块设备' },
  { id: 'shutdown', pattern: /\b(?:shutdown|reboot|poweroff|halt)\b/, reason: '关机或重启服务器' },
  { id: 'init-zero', pattern: /\binit\s+0\b/, reason: '切换到关机运行级' },
  { id: 'systemctl-destructive', pattern: /\bsystemctl\s+(?:stop|disable|mask|poweroff|reboot|halt|kill)\b/, reason: '停止或屏蔽系统服务' },
  { id: 'kill-all', pattern: /\b(?:kill|pkill)\s+-9\b/, reason: '强制杀死进程' },
  { id: 'account-delete', pattern: /\b(?:userdel|groupdel)\b/, reason: '删除系统账户或用户组' },
  { id: 'password-change', pattern: /\bpasswd\b/, reason: '修改账户密码' },
  { id: 'chmod-root', pattern: /\bchmod\s+(?:-R\s+)?(?:777|a\+rwx)\s+\//, reason: '放宽根目录权限' },
  { id: 'chown-root', pattern: /\bchown\s+-R\s+\S+\s+\//, reason: '递归修改根目录属主' },
  { id: 'firewall-flush', pattern: /\b(?:iptables\s+-F|ufw\s+disable|nft\s+flush)\b/, reason: '清空或关闭防火墙' },
  { id: 'truncate-zero', pattern: /\btruncate\s+-s\s*0\b/, reason: '清空文件内容' },
  { id: 'etc-overwrite', pattern: /(?:>{1,2}\s*\/etc\/|\btee\s+(?:-a\s+)?\/etc\/)/, reason: '覆盖系统配置' },
  { id: 'crontab-remove', pattern: /\bcrontab\s+-r\b/, reason: '删除全部定时任务' },
  { id: 'docker-prune', pattern: /\bdocker\s+(?:system\s+prune|volume\s+rm|rm\s+-f)\b/, reason: '删除容器、镜像或数据卷' },
  { id: 'kubectl-delete', pattern: /\bkubectl\s+delete\b/, reason: '删除 Kubernetes 资源' },
  {
    id: 'sql-drop',
    pattern: /\b(?:mysql|mariadb|psql|sqlite3|mongo|mongosh)\b[\s\S]*\b(?:drop|truncate)\s+(?:database|table)\b/i,
    reason: '删除数据库或数据表',
    raw: true,
  },
  {
    id: 'sql-drop-generic',
    pattern: /\b(?:drop|truncate)\s+(?:database|table)\b/i,
    reason: '删除数据库或数据表',
  },
  { id: 'curl-pipe-shell', pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|k)?sh\b/, reason: '从网络下载并直接执行脚本' },
  { id: 'sudo', pattern: /\bsudo\b/, reason: '以 root 权限执行' },
  { id: 'su-root', pattern: /\bsu\s+(?:-\s*)?root\b/, reason: '切换到 root' },
  { id: 'git-destructive', pattern: /\bgit\s+(?:reset\s+--hard|clean\s+-[A-Za-z]*f)\b/, reason: '丢弃未提交的代码' },
  { id: 'npm-publish', pattern: /\bnpm\s+publish\b/, reason: '发布软件包' },
  { id: 'terraform-destroy', pattern: /\bterraform\s+(?:destroy|apply)\b/, reason: '变更云基础设施' },
  { id: 'fork-bomb', pattern: /:\(\)\s*\{\s*:\|:&\s*\};:/, reason: 'fork 炸弹' },
]

/** Remove quoted text so `echo "rm -rf /"` is not treated as a deletion. */
function stripQuoted(command: string): string {
  return command.replace(/'[^']*'/g, "''").replace(/"[^"]*"/g, '""')
}

/** Classify one command; the reasons are safe to show to the user. */
export function assessCommandRisk(command: string): RiskAssessment {
  const stripped = stripQuoted(command)
  const reasons: string[] = []
  const matched: string[] = []
  for (const rule of RULES) {
    const source = rule.raw === true ? command : stripped
    if (rule.pattern.test(source)) {
      if (!matched.includes(rule.id)) matched.push(rule.id)
      if (!reasons.includes(rule.reason)) reasons.push(rule.reason)
    }
  }
  return { high: matched.length > 0, reasons, matched }
}

/** One-line human summary used in approval prompts and audit lines. */
export function describeRisk(assessment: RiskAssessment): string {
  return assessment.reasons.length > 0 ? assessment.reasons.join('、') : '常规命令'
}
