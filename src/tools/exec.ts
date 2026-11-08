/** The command-execution tool: risk gate, sudo, timeout, bounded output, audit. */

import { defineTool } from '@deepseek-ai/dsh-tools'
import { requireApproval } from '../approval.js'
import type { ToolDeps } from '../deps.js'
import { formatBytes } from '../output.js'
import { assessCommandRisk } from '../risk.js'
import { parseSudoPrefix, resolvePrivilege } from '../sudo.js'
import { SshHostsError } from '../types.js'
import type { ExecResult } from '../types.js'

interface ExecArgs {
  server: string
  command: string
  cwd?: string
  timeoutMs?: number
  maxOutputBytes?: number
  privileged?: boolean
}

function renderResult(value: ExecResult): string {
  const status =
    value.exitCode === null
      ? 'exit: 无（连接已关闭）'
      : value.exitCode === 0
        ? 'exit: 0（成功）'
        : `exit: ${value.exitCode}（命令失败，但 SSH 连接与执行通道正常）`
  const lines = [
    `SSH ${value.server}  ${status}  耗时 ${value.durationMs} ms`,
    `$ ${value.command}`,
    `cwd: ${value.cwd}`,
  ]
  if (value.privileged) {
    lines.push(`提权: sudo（${value.privilegeMode === 'password' ? '密码模式' : 'NOPASSWD 模式'}）`)
  }
  lines.push(
    `--- stdout（${formatBytes(Buffer.byteLength(value.stdout, 'utf8'))}）---`,
    value.stdout.length > 0 ? value.stdout : '（空）',
    `--- stderr（${formatBytes(Buffer.byteLength(value.stderr, 'utf8'))}）---`,
    value.stderr.length > 0 ? value.stderr : '（空）',
  )
  if (value.timedOut) lines.push('[已超时并被中断：远端命令可能仍在执行，输出可能不完整]')
  if (value.truncated) lines.push(`[输出已截断：原始共 ${formatBytes(value.originalBytes)}，以上保留了开头和结尾]`)
  if (value.approval === 'granted') lines.push('[高风险命令已由用户批准一次]')
  if (value.approval === 'policy-allow') lines.push('[高风险命令按 highRiskPolicy=allow 执行]')
  if (value.approval === 'full-access') lines.push('[完全权限会话：审批提示已关闭，高风险命令按已授权执行]')
  return lines.join('\n')
}

/** Register `ssh_exec`. */
export function registerExecTool(ctx: { tools: { register(definition: ReturnType<typeof defineTool>): () => void } }, deps: ToolDeps): void {
  ctx.tools.register(
    defineTool<ExecArgs, ExecResult>({
      name: 'ssh_exec',
      description:
        'Run one shell command on a configured Linux server over SSH and return exitCode, stdout, stderr, duration, timeout, and truncation state. ' +
        'Use it for inspection, builds, service checks, and other remote operations; prefer ssh_read_file/ssh_write_file for file content, and ssh_services to locate a service directory. ' +
        'A non-zero exit is a normal result, not a tool error. Commands classified as high risk (recursive delete, shutdown, mkfs, dd, sudo, firewall flush, database drop, …) require one-shot human approval; in a 「完全权限」 session (approval prompts disabled) they run and are marked full-access. ' +
        'To run as root, pass privileged: true or start the command with sudo (the leading sudo is rewritten to use the host sudo configuration; a plain `sudo cmd` becomes the plugin-managed sudo). The host must have a user-configured sudo policy; no password ever appears in the arguments. ' +
        'The working directory must be inside the server allowlist; commands that obviously write files (redirection, tee, sed -i, cp/mv/rm/touch) must run inside editablePaths — privileged commands are exempt from that edit guard but still respect deniedPaths. ' +
        'Scratch and process files belong in the host\'s temp directory (tempDir, /tmp by default, always readable and writable unless the deployment disabled it): create one subdirectory per task there (e.g. /tmp/dsh-<task>) and remove it when you are done, so no temporary files are left in service directories or the login home. ' +
        'Commands are audited. Output above maxOutputBytes keeps its head and tail with an explicit truncation marker.',
      parameters: {
        server: { type: 'string', required: true, description: 'Host id or alias from ssh_host_list.' },
        command: { type: 'string', required: true, description: 'Shell command to run, e.g. "uname -a && whoami". Avoid interactive or full-screen programs.' },
        cwd: { type: 'string', description: 'Remote working directory; defaults to the server defaultCwd or login home. Must be inside allowedPaths; edit-like commands must start in an editable root, so use the temp directory as cwd for scratch work.' },
        timeoutMs: { type: 'integer', description: 'Timeout in milliseconds; bounded by the plugin maxTimeoutMs. Defaults to timeoutMs config.' },
        maxOutputBytes: { type: 'integer', description: 'Per-stream output cap; bounded by 16 MiB. Defaults to maxOutputBytes config.' },
        privileged: { type: 'boolean', description: 'Run the command through the host sudo policy (root by default). Requires the user-configured sudo on that host; audited as high risk.' },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            server: { type: 'string', required: true },
            command: { type: 'string', required: true },
            cwd: { type: 'string', required: true },
            exitCode: { oneOf: [{ type: 'integer' }, { type: 'null' }], required: true },
            stdout: { type: 'string', required: true },
            stderr: { type: 'string', required: true },
            durationMs: { type: 'integer', required: true },
            timedOut: { type: 'boolean', required: true },
            truncated: { type: 'boolean', required: true },
            originalBytes: { type: 'integer', required: true },
            approval: { type: 'string', required: true, enum: ['not-required', 'granted', 'policy-allow', 'full-access'] },
            privileged: { type: 'boolean', required: true },
            privilegeMode: { oneOf: [{ type: 'string', enum: ['nopasswd', 'password'] }, { type: 'null' }], required: true },
          },
        },
        render: (_args, value) => [{ type: 'text', text: renderResult(value) }],
      },
      async execute(args, exec) {
        const host = await deps.store.find(args.server)
        if (host.readOnly) {
          throw new SshHostsError('READ_ONLY', `服务器 ${host.alias} 处于只读模式`, '请改用 ssh_read_file 或 ssh_download；如需执行命令请由用户关闭 readOnly')
        }
        const parsed = parseSudoPrefix(args.command)
        if (parsed.unsupported.length > 0) {
          throw new SshHostsError(
            'SUDO_FLAGS_UNSUPPORTED',
            `sudo 参数不受支持：${parsed.unsupported.join(' ')}`,
            '请去掉这些 sudo 参数，改用 privileged: true；插件会按主机的 sudo 配置自动加上 -S/-n、-H 与目标用户',
          )
        }
        const command = parsed.privileged ? parsed.command : args.command
        const risk = assessCommandRisk(args.command)
        // Approve the intent before touching the sudo configuration: a denied
        // high-risk command must not depend on how the host is set up.
        const approval = await requireApproval(deps, exec, host, args.command, risk)
        if (command.trim().length === 0) {
          throw new SshHostsError('INVALID_COMMAND', '命令不能为空', '请提供要执行的 shell 命令')
        }
        const privilege = await resolvePrivilege(deps, host, {
          privileged: args.privileged === true || parsed.privileged,
          ...(parsed.user === undefined ? {} : { user: parsed.user }),
        })
        const result = await deps.manager.exec(host, command, {
          ...(args.cwd === undefined ? {} : { cwd: args.cwd }),
          ...(args.timeoutMs === undefined ? {} : { timeoutMs: args.timeoutMs }),
          ...(args.maxOutputBytes === undefined ? {} : { maxOutputBytes: args.maxOutputBytes }),
          ...(privilege === undefined ? {} : { privilege }),
          signal: exec.signal,
        })
        result.approval = approval
        await deps.audit.append({
          action: 'exec',
          server: host.alias,
          hostId: host.id,
          user: host.username,
          command,
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          truncated: result.truncated,
          approval,
          privileged: result.privileged,
          ok: result.exitCode === 0,
        })
        return result
      },
      presentCall: (args) => ({
        card: 'terminal',
        title: `${args.privileged === true ? 'sudo ' : ''}${args.command}`,
        description: `ssh_exec · ${args.server}`,
        ...(args.cwd === undefined ? {} : { cwd: args.cwd }),
      }),
      presentResult: (args, result) => {
        const text = result.content.map((block) => (block.type === 'text' ? block.text : '')).join('\n')
        return { card: 'terminal', title: `${args.server}: ${args.command}`, output: text.slice(0, 8_000) }
      },
    }),
  )
}
