/**
 * Session permission preset detection.
 *
 * The plugin asks the Harness two questions before it gates anything:
 *
 * 1. `approval` — is this session's approval policy `ask` or `never`? Under
 *    `never` no prompt can be shown at all: the approval service rejects every
 *    request deterministically without consulting an answerer.
 * 2. `sandboxPolicy` — is this session's file sandbox `danger-full-access`
 *    (the Web GUI's “完全权限” preset) or one of the restricted modes?
 *
 * Both services are optional: a headless composition may omit them, and the
 * plugin must keep working (fail closed) when it cannot tell. Only the exact
 * `never` value counts as “prompts disabled”; anything unexpected keeps the
 * old `ask` behaviour so a future Harness change can never silently widen
 * permissions.
 */

import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { ApprovalPolicy, SandboxMode, SessionTrust, TrustResolver } from './deps.js'

interface ApprovalPolicyReader {
  effectivePolicy?(session: unknown): unknown
}

interface SandboxPolicyReader {
  resolve?(request?: { session?: unknown }): unknown
}

export interface TrustReaders {
  approval?: unknown
  sandbox?: unknown
}

const UNKNOWN_TRUST: SessionTrust = {
  approvalPolicy: 'unknown',
  sandboxMode: 'unknown',
  promptsDisabled: false,
  fullAccess: false,
}

function readApprovalPolicy(service: unknown, session: unknown): ApprovalPolicy {
  if (typeof service !== 'object' || service === null) return 'unknown'
  const method = (service as ApprovalPolicyReader).effectivePolicy
  if (typeof method !== 'function' || session === undefined) return 'unknown'
  try {
    const value = method.call(service, session)
    return value === 'never' || value === 'ask' ? value : 'unknown'
  } catch {
    return 'unknown'
  }
}

function readSandboxMode(service: unknown, session: unknown): SandboxMode {
  if (typeof service !== 'object' || service === null) return 'unknown'
  const method = (service as SandboxPolicyReader).resolve
  if (typeof method !== 'function' || session === undefined) return 'unknown'
  try {
    const resolved = method.call(service, { session })
    const mode = typeof resolved === 'object' && resolved !== null ? (resolved as { mode?: unknown }).mode : undefined
    return mode === 'read-only' || mode === 'workspace-write' || mode === 'danger-full-access' ? mode : 'unknown'
  } catch {
    return 'unknown'
  }
}

/**
 * Resolve the effective permission preset for one tool call.
 *
 * `fullAccess` is deliberately narrow: it requires the approval service to say
 * `never` *and* the sandbox to be `danger-full-access` (or absent, meaning no
 * file sandbox is mounted at all). A `never` policy over a restricted sandbox
 * only disables prompts; risky commands then fail closed with an explanation.
 */
export function resolveSessionTrust(readers: TrustReaders, exec: ToolRunContext): SessionTrust {
  const session = exec.agent?.session
  if (session === undefined) return UNKNOWN_TRUST
  const approvalPolicy = readApprovalPolicy(readers.approval, session)
  const sandboxMode = readSandboxMode(readers.sandbox, session)
  const promptsDisabled = approvalPolicy === 'never'
  return {
    approvalPolicy,
    sandboxMode,
    promptsDisabled,
    fullAccess: promptsDisabled && (sandboxMode === 'danger-full-access' || sandboxMode === 'unknown'),
  }
}

/** Build the resolver the plugin hands to every tool through `ToolDeps`. */
export function createTrustResolver(readers: () => TrustReaders): TrustResolver {
  return (exec) => resolveSessionTrust(readers(), exec)
}

/** One-line description used in errors and debug lines. */
export function describeTrust(trust: SessionTrust): string {
  const approval = trust.approvalPolicy === 'ask' ? '审批策略 ask' : trust.approvalPolicy === 'never' ? '审批策略 never（不弹审批）' : '审批策略未知'
  const sandbox =
    trust.sandboxMode === 'danger-full-access'
      ? '完全权限'
      : trust.sandboxMode === 'workspace-write'
        ? '工作区内修改'
        : trust.sandboxMode === 'read-only'
          ? '仅可查看'
          : '沙箱策略未知'
  return `${approval}，${sandbox}`
}
