/**
 * dsh-plugin-ssh-hosts — multiple Linux servers over SSH.
 *
 * The plugin owns its data under `$DSH_HOME/ssh-hosts` (or `dataDir`): the host
 * inventory, an AES-256-GCM credential store, TOFU fingerprints, transfers,
 * and an audit log. Passwords, passphrases, and private-key bytes never enter a
 * tool result, the session log, or a debug line.
 */

import { readFile } from 'node:fs/promises'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import { AuditLog } from './audit.js'
import { Config, resolveDataDir, withDefaults, type SshHostsConfig } from './config.js'
import type { ApprovalRequest, ApprovalService, ToolDeps } from './deps.js'
import { ensureDir } from './fs-util.js'
import { registerHistoryRoute } from './history.js'
import { HostStore } from './hosts.js'
import { createDebugLogger } from './redact.js'
import { SecretStore } from './secrets.js'
import { SessionConsentGate } from './session-consent.js'
import { createTrustResolver } from './session-policy.js'
import { SshManager, type ResolvedCredentials } from './ssh.js'
import { registerExecTool } from './tools/exec.js'
import { registerFileTools } from './tools/files.js'
import { registerHostTools } from './tools/host.js'
import { registerHostsUiRoute } from './ui-api.js'
import type { HostRecord } from './types.js'
import { describeError, SshHostsError } from './types.js'

export const name = 'ssh-hosts'
export const inject = ['tools']
export { Config }

/** Register every `ssh_*` tool and the connection pool's cleanup hook. */
export function apply(ctx: Context, rawConfig: Partial<SshHostsConfig> | undefined): void {
  const config = withDefaults(rawConfig)
  const dataDir = resolveDataDir(config)
  const debug = createDebugLogger(config.debug)
  void ensureDir(dataDir, 0o700).catch((error: unknown) => {
    debug(`data directory unavailable: ${error instanceof Error ? error.message : String(error)}`)
  })

  const store = new HostStore(dataDir)
  const secrets = new SecretStore({ dir: dataDir, backend: config.secretsBackend, envPrefix: config.envPrefix })
  const audit = new AuditLog(dataDir, config.audit)

  const resolveCredentials = async (host: HostRecord): Promise<ResolvedCredentials> => {
    if (host.auth.type === 'password') {
      const password = await secrets.get(host.auth.secretRef)
      if (password === undefined) {
        throw new SshHostsError(
          'CREDENTIAL_MISSING',
          `服务器 ${host.alias} 还没有可用的密码凭据`,
          '请由用户在本机运行插件自带的 scripts/dsh-ssh.mjs 录入密码，或使用 env 后端设置环境变量；模型不会接收密码',
        )
      }
      return { password }
    }
    let privateKey: Buffer
    try {
      privateKey = await readFile(host.auth.privateKeyPath)
    } catch (error) {
      throw new SshHostsError(
        'CREDENTIAL_MISSING',
        `无法读取服务器 ${host.alias} 的私钥文件`,
        `请由用户确认本机路径 ${host.auth.privateKeyPath} 可读；私钥内容不会出现在结果中`,
        error,
      )
    }
    let passphrase: string | undefined
    if (host.auth.passphraseRef !== undefined) {
      passphrase = await secrets.get(host.auth.passphraseRef)
    }
    return {
      privateKey,
      ...(passphrase === undefined ? {} : { passphrase }),
    }
  }

  const manager = new SshManager({
    config,
    credentials: resolveCredentials,
    debug,
    onFingerprint: async (host, fingerprint) => {
      await store.setFingerprint(host.id, fingerprint)
      debug(`learned host key for ${host.alias}: ${fingerprint}`)
    },
  })

  /**
   * Cordis refuses to read a service the plugin did not inject, and either
   * service may be absent or mount after this plugin, so every lookup is
   * guarded and the resolved references are cached through `ctx.inject`.
   */
  const optionalService = <T>(scope: Context, serviceName: string): T | undefined => {
    try {
      return scope.get<T>(serviceName)
    } catch {
      return undefined
    }
  }

  let approvalService: ApprovalService | undefined = optionalService<ApprovalService>(ctx, 'approval')
  let sandboxPolicyService: unknown = optionalService<unknown>(ctx, 'sandboxPolicy')
  const injecting = ctx as unknown as {
    inject?: (deps: string[], execute: (scope: Context) => void | (() => void)) => void
  }
  if (typeof injecting.inject === 'function') {
    injecting.inject(['approval'], (scope: Context) => {
      approvalService = optionalService<ApprovalService>(scope, 'approval')
    })
    injecting.inject(['sandboxPolicy'], (scope: Context) => {
      sandboxPolicyService = optionalService<unknown>(scope, 'sandboxPolicy')
    })
  }

  const approval: ApprovalService = {
    request(request: ApprovalRequest) {
      const service = approvalService ?? optionalService<ApprovalService>(ctx, 'approval')
      if (service === undefined) {
        throw new SshHostsError(
          'APPROVAL_UNAVAILABLE',
          '高风险命令需要人工审批，但当前组合没有挂载审批服务',
          '请启用审批组件后重试，或由用户调整 highRiskPolicy',
        )
      }
      return service.request(request)
    },
  }

  /** Effective permission preset (“完全权限” detection) for one tool call. */
  const trust = createTrustResolver(() => ({
    approval: approvalService ?? optionalService(ctx, 'approval'),
    sandbox: sandboxPolicyService ?? optionalService(ctx, 'sandboxPolicy'),
  }))

  const deps: ToolDeps = { config, dataDir, store, secrets, manager, audit, approval, trust, debug }

  const sessionConsent = new SessionConsentGate(config, approval, debug, async (server) => {
    try {
      const host = await store.find(server)
      return { id: host.id, alias: host.alias, host: host.host, username: host.username }
    } catch {
      // Unknown hosts fall through to the tool's own HOST_NOT_FOUND error; we
      // do not want to ask the user to approve a server that cannot be used.
      return undefined
    }
  }, trust)

  // Every plugin tool goes through the same consent gate. Keeping the wrapper
  // here (instead of in eleven execute bodies) means a future tool cannot
  // silently opt out of the per-session/per-server rule.
  const gatedCtx = {
    tools: {
      register(definition: ToolDefinition) {
        const description =
          config.sessionConsent === 'ask'
            ? `${definition.description} The first ssh_* call for a given server (or for the host inventory) in a new session asks the user for permission; other servers need their own approval, and a denial must not be retried automatically. In a session with approval prompts disabled (「完全权限」), that authorization is granted automatically.`
            : definition.description
        return ctx.tools.register({
          ...definition,
          description,
          async execute(args, exec) {
            try {
              await sessionConsent.ensure(exec, definition.name, args)
              return await definition.execute(args, exec)
            } catch (error) {
              // A tool failure carries only its message to the model, so the
              // actionable hint (for example "put scratch files in /tmp") must
              // live inside that message; the stable code stays in the suffix.
              if (error instanceof SshHostsError && error.hint !== null) {
                throw new Error(describeError(error), { cause: error })
              }
              throw error
            }
          },
        })
      },
    },
  } as unknown as Context

  registerHostTools(gatedCtx, deps)
  registerExecTool(gatedCtx, deps)
  registerFileTools(gatedCtx, deps)

  // Read-only endpoint behind the Web "SSH command history" panel.
  registerHistoryRoute(ctx, {
    dataDir,
    auditEnabled: config.audit,
    debug,
    hosts: () => store.list(),
  })

  // Read/write endpoints behind the Web "SSH 服务器" management page. The
  // route itself enforces loopback-only access and a same-page write header.
  registerHostsUiRoute(ctx, { dataDir, config, store, secrets, manager, audit, debug })

  ctx.effect(() => {
    return () => {
      sessionConsent.dispose()
      void manager.dispose()
    }
  })
  debug(`mounted with dataDir=${dataDir} backend=${config.secretsBackend} highRiskPolicy=${config.highRiskPolicy}`)
}

export { withDefaults, resolveDataDir }
export type { SshHostsConfig }
