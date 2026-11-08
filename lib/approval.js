/** Human approval for commands classified as high risk. */
import { redact } from './redact.js';
import { describeRisk } from './risk.js';
import { describeTrust } from './session-policy.js';
import { SshHostsError } from './types.js';
/**
 * Apply the configured high-risk policy.
 *
 * Order of precedence:
 * 1. `highRiskPolicy` — an explicit deployment decision (`allow`/`deny`).
 * 2. Session permission preset — under “完全权限” (approval `never` plus
 *    `danger-full-access`) prompts cannot be shown, and the user has already
 *    accepted that risk, so risky commands are allowed and marked
 *    `full-access`. A `never` policy over a restricted sandbox still fails
 *    closed with an explanatory error.
 * 3. Interactive `ask` — always fails closed when the answerer is missing,
 *    the caller has no agent, or the user does not grant.
 */
export async function requireApproval(deps, exec, host, command, risk) {
    if (!risk.high)
        return 'not-required';
    const reason = `在 ${host.alias}（${host.username}@${host.host}）执行高风险命令（${describeRisk(risk)}）：${redact(command)}`;
    if (deps.config.highRiskPolicy === 'allow') {
        deps.debug(`high-risk allowed by policy: ${redact(command)}`);
        return 'policy-allow';
    }
    if (deps.config.highRiskPolicy === 'deny') {
        throw new SshHostsError('HIGH_RISK_DENIED', `命令被判定为高风险并已拒绝：${describeRisk(risk)}`, '请由用户调整 highRiskPolicy，或改用低风险命令');
    }
    const trust = deps.trust(exec);
    if (trust.promptsDisabled) {
        if (trust.fullAccess && deps.config.trustFullAccess) {
            deps.debug(`high-risk allowed by full-access session (${describeTrust(trust)}): ${redact(command)}`);
            return 'full-access';
        }
        throw new SshHostsError('APPROVAL_POLICY_DENIED', `本次会话不弹审批（${describeTrust(trust)}），高风险命令按失败关闭处理：${describeRisk(risk)}`, trust.fullAccess
            ? '插件配置 trustFullAccess=false，因此完全权限下仍拒绝高风险命令；请由用户改回 true，或改用低风险命令'
            : '如需执行 sudo 等高风险命令，请把会话权限预设切换为「完全权限」，或由用户把 highRiskPolicy 设为 allow');
    }
    if (exec.agent === undefined) {
        throw new SshHostsError('APPROVAL_UNAVAILABLE', '高风险命令需要人工审批，但当前调用没有关联的 Agent', '请从会话中调用该工具，或由用户调整 highRiskPolicy');
    }
    if (deps.approval === undefined) {
        throw new SshHostsError('APPROVAL_UNAVAILABLE', '高风险命令需要人工审批，但当前组合没有挂载审批服务', '请启用审批组件后重试，或由用户调整 highRiskPolicy');
    }
    let outcome;
    try {
        outcome = await deps.approval.request({
            agent: exec.agent,
            toolName: 'ssh_exec',
            callId: exec.callId,
            reason,
            displayReason: {
                en: `High-risk SSH command on ${host.alias}: ${describeRisk(risk)}`,
                zh: `在 ${host.alias} 上执行高风险命令：${describeRisk(risk)}`,
            },
            ...(exec.signal === undefined ? {} : { signal: exec.signal }),
        });
    }
    catch (error) {
        throw new SshHostsError('APPROVAL_UNAVAILABLE', '人工审批请求失败', '请由用户检查审批组件或调整 highRiskPolicy', error);
    }
    if (outcome === 'allowed-once')
        return 'granted';
    throw new SshHostsError('APPROVAL_DENIED', `高风险命令未获批准（${outcome}）`, '请询问用户是否允许该操作，或改用低风险方案');
}
