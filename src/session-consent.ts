/**
 * Per-server consent for the SSH plugin.
 *
 * DSH's approval seam is deliberately one-shot: every call to
 * `approval.request()` needs a fresh human decision. Asking before every
 * `ssh_*` call would make the plugin unusable, so this gate remembers a
 * positive answer for the rest of the session — but only for the exact target
 * the user approved. The target is one configured server (keyed by its stable
 * host id, not its alias), plus one separate scope for the local host
 * inventory (`ssh_host_list` / `ssh_host_add`). Approving server A never
 * approves server B, and a new session starts with no grants at all.
 *
 * Grants live only in this process: a Harness restart asks again. A denial is
 * never remembered, so a user who changes their mind can approve a later call
 * without opening a new session.
 *
 * A session whose approval policy is `never` (the GUI's “完全权限”) can never
 * show a prompt. With `trustFullAccess` enabled the gate records the grant
 * without asking; that is the only way the plugin can work in that preset.
 */

import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { SshHostsConfig } from './config.js'
import type { ApprovalOutcome, ApprovalService, TrustResolver } from './deps.js'
import type { DebugLogger } from './redact.js'
import { describeTrust } from './session-policy.js'
import { SshHostsError } from './types.js'

type Decision = 'granted' | 'denied'

/** What one consent request is about. */
interface ConsentTarget {
  /** Stable map key: `inventory:read`, `inventory:write`, or `server:<host id>`. */
  key: string
  /** Human-facing target name used in the approval prompt. */
  label: string
  scope: 'inventory-read' | 'inventory-write' | 'server'
}

/** Resolve an alias or id to the stable host identity a grant is keyed by. */
export type ServerResolver = (
  server: string,
) => Promise<{ id: string; alias: string; host: string; username: string } | undefined>

/** Tools that address one server through their required `server` argument. */
const SERVER_TOOLS = new Set([
  'ssh_exec',
  'ssh_test',
  'ssh_read_file',
  'ssh_write_file',
  'ssh_upload',
  'ssh_download',
  'ssh_services',
  'ssh_host_update',
  'ssh_host_remove',
])

/** Tools that operate on the local host inventory instead of one server. */
const INVENTORY_TARGETS = new Map<string, ConsentTarget>([
  [
    'ssh_host_list',
    { key: 'inventory:read', label: 'SSH 主机清单（查看）', scope: 'inventory-read' },
  ],
  [
    'ssh_host_add',
    { key: 'inventory:write', label: 'SSH 主机清单（新增主机）', scope: 'inventory-write' },
  ],
])

/** Identify the durable conversation a tool call belongs to. */
function sessionKey(exec: ToolRunContext): string | undefined {
  const agent = exec.agent
  if (agent === undefined) return undefined
  const sessionId = agent.session?.id ?? agent.session?.header?.id
  if (typeof sessionId === 'string' && sessionId.length > 0) return `session:${sessionId}`
  // Some same-process callers have an agent but no materialized session. The
  // agent id is the session id in the current Harness, so this is still one
  // stable key per conversation instead of one key per call.
  if (typeof agent.id === 'string' && agent.id.length > 0) return `agent:${agent.id}`
  return undefined
}

/** Read the `server` argument without trusting its shape. */
function serverArgument(args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const value = (args as { server?: unknown }).server
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined
}

function consentUnavailable(toolName: string, cause?: unknown): SshHostsError {
  return new SshHostsError(
    'SESSION_CONSENT_UNAVAILABLE',
    `无法取得用户对 SSH 插件的使用授权（触发：${toolName}）`,
    '当前调用没有可用的审批通道；为避免模型在后台静默使用 SSH 插件，本次调用已按拒绝处理。请让用户在带审批界面的会话中重试，或由用户把 sessionConsent 配置为 allow。',
    cause,
  )
}

function consentDenied(target: ConsentTarget, toolName: string): SshHostsError {
  const subject =
    target.scope === 'server'
      ? `服务器 ${target.label}`
      : target.scope === 'inventory-read'
        ? 'SSH 主机清单（查看）'
        : 'SSH 主机清单（新增主机）'
  return new SshHostsError(
    'SESSION_CONSENT_DENIED',
    `用户或当前审批策略未允许本会话访问${subject}（触发：${toolName}）`,
    '本次调用没有执行任何远程操作。不要自动重试；如果用户随后明确表示同意，可以再次调用，插件会重新弹出该目标的授权请求。',
  )
}

/**
 * Ask the user once per session and per target, before the tool body runs.
 * Concurrent first calls for the same target share one in-flight request, so a
 * model that issues a parallel batch cannot produce several prompts for the
 * same server.
 */
export class SessionConsentGate {
  private readonly granted = new Set<string>()
  private readonly pending = new Map<string, Promise<Decision>>()

  constructor(
    private readonly config: SshHostsConfig,
    private readonly approval: ApprovalService | undefined,
    private readonly debug: DebugLogger,
    private readonly resolveServer: ServerResolver,
    private readonly trust: TrustResolver,
  ) {}

  /** Throw unless this session may use the target of this call right now. */
  async ensure(exec: ToolRunContext, toolName: string, args: unknown): Promise<void> {
    if (this.config.sessionConsent === 'allow') return
    if (this.config.sessionConsent === 'deny') {
      throw new SshHostsError(
        'SESSION_CONSENT_DENIED',
        'SSH 插件已被配置为禁止使用（sessionConsent=deny）',
        '由用户把 sessionConsent 改为 ask 或 allow 后重新加载插件。',
      )
    }

    const session = sessionKey(exec)
    if (session === undefined) throw consentUnavailable(toolName)
    const target = await this.targetOf(toolName, args)
    // An unknown server or malformed arguments are left to the tool itself:
    // asking the user about a target that cannot be used would be noise, and
    // the tool's own error (HOST_NOT_FOUND / invalid arguments) is more useful.
    if (target === undefined) return
    const key = `${session}|${target.key}`
    if (this.granted.has(key)) return

    // “完全权限” sessions cannot show a prompt: the approval service answers
    // `never` without consulting any answerer. Failing closed here made every
    // ssh_* tool unusable in that preset, so the gate records a process-local
    // grant instead (still per session and per target, still audited).
    const trust = this.trust(exec)
    if (trust.promptsDisabled && this.config.trustFullAccess) {
      this.granted.add(key)
      this.debug(`session consent auto-granted for ${key} (${describeTrust(trust)}) via ${toolName}`)
      return
    }

    let request = this.pending.get(key)
    if (request === undefined) {
      request = this.requestConsent(exec, key, target, toolName)
      this.pending.set(key, request)
    }

    try {
      const decision = await request
      if (decision === 'denied') throw consentDenied(target, toolName)
    } finally {
      // Only the initiating call removes the shared promise; late waiters see
      // the same settled result and must not delete a newer request.
      if (this.pending.get(key) === request) this.pending.delete(key)
    }
  }

  /** Drop every in-memory grant; used when the plugin is disposed. */
  dispose(): void {
    this.granted.clear()
    this.pending.clear()
  }

  private async targetOf(toolName: string, args: unknown): Promise<ConsentTarget | undefined> {
    const inventory = INVENTORY_TARGETS.get(toolName)
    if (inventory !== undefined) return inventory
    if (!SERVER_TOOLS.has(toolName)) return undefined
    const server = serverArgument(args)
    if (server === undefined) return undefined
    const resolved = await this.resolveServer(server)
    if (resolved === undefined) return undefined
    return {
      key: `server:${resolved.id}`,
      label: `${resolved.alias}（${resolved.username}@${resolved.host}）`,
      scope: 'server',
    }
  }

  private async requestConsent(
    exec: ToolRunContext,
    key: string,
    target: ConsentTarget,
    toolName: string,
  ): Promise<Decision> {
    const agent = exec.agent
    if (agent === undefined || this.approval === undefined) throw consentUnavailable(toolName)

    const isServer = target.scope === 'server'
    const isInventoryRead = target.scope === 'inventory-read'
    const reason = isServer
      ? `本会话第一次使用服务器 ${target.label}（触发工具：${toolName}）。批准后，本会话对该服务器的后续 ssh_* 调用不再逐次询问；其它服务器仍需单独申请。`
      : isInventoryRead
        ? `本会话第一次查看 SSH 主机清单（触发工具：${toolName}）。批准后，本会话的清单查看不再逐次询问；这不授予任何服务器的访问权限。`
        : `本会话第一次新增 SSH 主机（触发工具：${toolName}）。批准后，本会话的新增主机操作不再逐次询问；这不授予任何服务器的访问权限。`
    const displayReason = isServer
      ? {
          en:
            `Allow the model to use server ${target.label} in this session? ` +
            `It asked to call ${toolName} for the first time here. ` +
            'If you allow it, later ssh_* calls for this server in this session will not ask again; other servers still need their own approval.',
          zh:
            `允许本会话使用服务器 ${target.label} 吗？模型首次请求调用 ${toolName}；` +
            '批准后，本会话对该服务器的后续 ssh_* 调用不再逐次询问，其它服务器仍需单独申请。',
        }
      : isInventoryRead
        ? {
            en:
              `Allow the model to view the SSH host inventory in this session? ` +
              `It asked to call ${toolName} for the first time here. ` +
              'This does not grant access to any server; each server needs its own approval.',
            zh:
              `允许本会话查看 SSH 主机清单吗？模型首次请求调用 ${toolName}；` +
              '这不会授予任何服务器的访问权限，每台服务器仍需单独申请。',
          }
        : {
            en:
              `Allow the model to add a server to the SSH host inventory in this session? ` +
              `It asked to call ${toolName} for the first time here. ` +
              'This does not grant access to any server; using a server needs its own approval.',
            zh:
              `允许本会话新增 SSH 主机吗？模型首次请求调用 ${toolName}；` +
              '这不授予任何服务器的访问权限，使用服务器仍需单独申请。',
          }

    let outcome: ApprovalOutcome
    try {
      outcome = await this.approval.request({
        agent,
        toolName,
        callId: exec.callId,
        reason,
        displayReason,
        signal: exec.signal,
      })
    } catch (error) {
      throw consentUnavailable(toolName, error)
    }

    switch (outcome) {
      case 'allowed-once':
        this.granted.add(key)
        this.debug(`session consent granted (${key}) via ${toolName}`)
        return 'granted'
      case 'rejected':
        this.debug(`session consent rejected (${key}) via ${toolName}`)
        return 'denied'
      case 'cancelled':
        throw new SshHostsError(
          'SESSION_CONSENT_CANCELLED',
          'SSH 插件使用授权请求被取消',
          '本次调用没有执行任何远程操作；如仍需使用，请在用户可交互时重试。',
        )
      case 'unavailable':
        throw consentUnavailable(toolName)
    }
  }
}
