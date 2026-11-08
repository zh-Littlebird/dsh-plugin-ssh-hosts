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
const UNKNOWN_TRUST = {
    approvalPolicy: 'unknown',
    sandboxMode: 'unknown',
    promptsDisabled: false,
    fullAccess: false,
};
function readApprovalPolicy(service, session) {
    if (typeof service !== 'object' || service === null)
        return 'unknown';
    const method = service.effectivePolicy;
    if (typeof method !== 'function' || session === undefined)
        return 'unknown';
    try {
        const value = method.call(service, session);
        return value === 'never' || value === 'ask' ? value : 'unknown';
    }
    catch {
        return 'unknown';
    }
}
function readSandboxMode(service, session) {
    if (typeof service !== 'object' || service === null)
        return 'unknown';
    const method = service.resolve;
    if (typeof method !== 'function' || session === undefined)
        return 'unknown';
    try {
        const resolved = method.call(service, { session });
        const mode = typeof resolved === 'object' && resolved !== null ? resolved.mode : undefined;
        return mode === 'read-only' || mode === 'workspace-write' || mode === 'danger-full-access' ? mode : 'unknown';
    }
    catch {
        return 'unknown';
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
export function resolveSessionTrust(readers, exec) {
    const session = exec.agent?.session;
    if (session === undefined)
        return UNKNOWN_TRUST;
    const approvalPolicy = readApprovalPolicy(readers.approval, session);
    const sandboxMode = readSandboxMode(readers.sandbox, session);
    const promptsDisabled = approvalPolicy === 'never';
    return {
        approvalPolicy,
        sandboxMode,
        promptsDisabled,
        fullAccess: promptsDisabled && (sandboxMode === 'danger-full-access' || sandboxMode === 'unknown'),
    };
}
/** Build the resolver the plugin hands to every tool through `ToolDeps`. */
export function createTrustResolver(readers) {
    return (exec) => resolveSessionTrust(readers(), exec);
}
/** One-line description used in errors and debug lines. */
export function describeTrust(trust) {
    const approval = trust.approvalPolicy === 'ask' ? '审批策略 ask' : trust.approvalPolicy === 'never' ? '审批策略 never（不弹审批）' : '审批策略未知';
    const sandbox = trust.sandboxMode === 'danger-full-access'
        ? '完全权限'
        : trust.sandboxMode === 'workspace-write'
            ? '工作区内修改'
            : trust.sandboxMode === 'read-only'
                ? '仅可查看'
                : '沙箱策略未知';
    return `${approval}，${sandbox}`;
}
