import assert from 'node:assert/strict'
import test from 'node:test'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import { requireApproval } from '../src/approval.js'
import { withDefaults } from '../src/config.js'
import type { SessionTrust, ToolDeps } from '../src/deps.js'
import { assessCommandRisk } from '../src/risk.js'
import { SecretStore } from '../src/secrets.js'
import { resolveSessionTrust, createTrustResolver, describeTrust } from '../src/session-policy.js'
import { wrapPrivilegedCommand } from '../src/ssh.js'
import { parseSudoPrefix, resolvePrivilege, sudoPasswordStatus, sudoSecretRef } from '../src/sudo.js'
import type { HostRecord } from '../src/types.js'
import { SshHostsError } from '../src/types.js'
import { tempDir } from './helpers.js'

const HOME = '/home/deploy'

function makeHost(overrides: Partial<HostRecord> = {}): HostRecord {
  const now = new Date(0).toISOString()
  return {
    id: 'host_11111111',
    alias: 'test-1',
    host: '10.0.0.9',
    port: 22,
    username: 'deploy',
    auth: { type: 'password', secretRef: 'host:host_11111111:password' },
    fingerprint: null,
    fingerprintPolicy: 'strict',
    allowedPaths: ['~'],
    editablePaths: [],
    services: [],
    deniedPaths: ['~/.ssh'],
    readOnly: false,
    tags: [],
    createdAt: now,
    updatedAt: now,
    ...overrides,
  }
}

function execFor(): ToolRunContext {
  return {
    agent: { id: 'agent-1', session: { id: 'session-1', header: { id: 'session-1' } } },
    callId: 'call-1',
    signal: new AbortController().signal,
    deferContext() {},
    concludeTurn() {},
  } as unknown as ToolRunContext
}

const UNKNOWN: SessionTrust = { approvalPolicy: 'unknown', sandboxMode: 'unknown', promptsDisabled: false, fullAccess: false }
const FULL_ACCESS: SessionTrust = {
  approvalPolicy: 'never',
  sandboxMode: 'danger-full-access',
  promptsDisabled: true,
  fullAccess: true,
}
const NEVER_RESTRICTED: SessionTrust = {
  approvalPolicy: 'never',
  sandboxMode: 'workspace-write',
  promptsDisabled: true,
  fullAccess: false,
}

async function fakeDeps(trust: SessionTrust, overrides: Partial<ToolDeps> = {}): Promise<ToolDeps> {
  const dir = await tempDir('dsh-ssh-sudo-')
  const secrets = new SecretStore({ dir, backend: 'file', envPrefix: 'SSH_HOST_' })
  return {
    config: withDefaults({ dataDir: dir, highRiskPolicy: 'ask', trustFullAccess: true }),
    dataDir: dir,
    secrets,
    approval: undefined,
    trust: () => trust,
    debug: () => undefined,
    ...overrides,
  } as unknown as ToolDeps
}

// ---------------------------------------------------------------------------
// Session policy detection
// ---------------------------------------------------------------------------

test('unknown services keep the conservative ask behaviour', () => {
  const trust = resolveSessionTrust({}, execFor())
  assert.deepEqual(trust, UNKNOWN)
  assert.equal(trust.promptsDisabled, false)
  assert.equal(trust.fullAccess, false)
})

test('approval never plus danger-full-access is full access', () => {
  const trust = resolveSessionTrust(
    {
      approval: { effectivePolicy: () => 'never' },
      sandbox: { resolve: () => ({ mode: 'danger-full-access' }) },
    },
    execFor(),
  )
  assert.equal(trust.approvalPolicy, 'never')
  assert.equal(trust.sandboxMode, 'danger-full-access')
  assert.equal(trust.promptsDisabled, true)
  assert.equal(trust.fullAccess, true)
  assert.match(describeTrust(trust), /完全权限/)
})

test('approval never over a restricted sandbox disables prompts without full access', () => {
  const trust = resolveSessionTrust(
    {
      approval: { effectivePolicy: () => 'never' },
      sandbox: { resolve: () => ({ mode: 'workspace-write' }) },
    },
    execFor(),
  )
  assert.equal(trust.promptsDisabled, true)
  assert.equal(trust.fullAccess, false)
})

test('an ask policy never auto-grants, whatever the sandbox says', () => {
  const trust = resolveSessionTrust(
    {
      approval: { effectivePolicy: () => 'ask' },
      sandbox: { resolve: () => ({ mode: 'danger-full-access' }) },
    },
    execFor(),
  )
  assert.equal(trust.promptsDisabled, false)
  assert.equal(trust.fullAccess, false)
})

test('a throwing or malformed policy service falls back to unknown', () => {
  const throwing = resolveSessionTrust(
    {
      approval: {
        effectivePolicy: () => {
          throw new Error('boom')
        },
      },
      sandbox: { resolve: () => 'nonsense' },
    },
    execFor(),
  )
  assert.equal(throwing.approvalPolicy, 'unknown')
  assert.equal(throwing.sandboxMode, 'unknown')
  const lazy = createTrustResolver(() => ({ approval: { effectivePolicy: () => 'ask' } }))
  assert.equal(lazy(execFor()).approvalPolicy, 'ask')
})

// ---------------------------------------------------------------------------
// High-risk approval under full access
// ---------------------------------------------------------------------------

test('full-access sessions allow high-risk commands without prompting', async () => {
  const deps = await fakeDeps(FULL_ACCESS)
  const command = 'sudo systemctl restart nginx'
  const decision = await requireApproval(deps, execFor(), makeHost(), command, assessCommandRisk(command))
  assert.equal(decision, 'full-access')
})

test('a never policy over a restricted sandbox fails closed with an explanation', async () => {
  const deps = await fakeDeps(NEVER_RESTRICTED)
  const command = 'sudo systemctl restart nginx'
  await assert.rejects(
    () => requireApproval(deps, execFor(), makeHost(), command, assessCommandRisk(command)),
    (error: unknown) =>
      error instanceof SshHostsError &&
      error.code === 'APPROVAL_POLICY_DENIED' &&
      /完全权限/.test(error.hint ?? ''),
  )
})

test('trustFullAccess=false restores fail-closed behaviour in full access', async () => {
  const deps = await fakeDeps(FULL_ACCESS, { config: withDefaults({ highRiskPolicy: 'ask', trustFullAccess: false }) })
  const command = 'sudo systemctl restart nginx'
  await assert.rejects(
    () => requireApproval(deps, execFor(), makeHost(), command, assessCommandRisk(command)),
    (error: unknown) => error instanceof SshHostsError && error.code === 'APPROVAL_POLICY_DENIED',
  )
})

test('ask sessions still use the approval service', async () => {
  let asked = 0
  const deps = await fakeDeps(UNKNOWN, {
    approval: {
      async request() {
        asked++
        return 'allowed-once' as const
      },
    },
  })
  const command = 'sudo systemctl restart nginx'
  const decision = await requireApproval(deps, execFor(), makeHost(), command, assessCommandRisk(command))
  assert.equal(decision, 'granted')
  assert.equal(asked, 1)
})

// ---------------------------------------------------------------------------
// Leading sudo parsing
// ---------------------------------------------------------------------------

test('parses a bare sudo prefix and keeps the command intact', () => {
  const parsed = parseSudoPrefix('sudo systemctl restart nginx')
  assert.equal(parsed.privileged, true)
  assert.equal(parsed.command, 'systemctl restart nginx')
  assert.deepEqual(parsed.unsupported, [])
})

test('parses -u/--user and ignores prompt-only flags', () => {
  const withUser = parseSudoPrefix('sudo -n -u postgres psql -c "select 1;  select 2"')
  assert.equal(withUser.user, 'postgres')
  assert.equal(withUser.command, 'psql -c "select 1;  select 2"', 'inner quoting and spacing survive')

  const inline = parseSudoPrefix('sudo -uroot whoami')
  assert.equal(inline.user, 'root')
  assert.equal(inline.command, 'whoami')

  const long = parseSudoPrefix('sudo --user=deploy id -u')
  assert.equal(long.user, 'deploy')
  assert.equal(long.command, 'id -u')
})

test('leading sudo chains keep everything after the prefix', () => {
  const parsed = parseSudoPrefix('sudo systemctl restart a && systemctl status a')
  assert.equal(parsed.command, 'systemctl restart a && systemctl status a')
})

test('unsupported sudo flags are reported instead of silently dropped', () => {
  const parsed = parseSudoPrefix('sudo -i whoami')
  assert.deepEqual(parsed.unsupported, ['-i'])
  const login = parseSudoPrefix('sudo --login whoami')
  assert.deepEqual(login.unsupported, ['--login'])
})

test('commands without a leading sudo are untouched', () => {
  const parsed = parseSudoPrefix('echo "sudo not at the front"')
  assert.equal(parsed.privileged, false)
  assert.equal(parsed.command, 'echo "sudo not at the front"')
})

// ---------------------------------------------------------------------------
// Wrapping
// ---------------------------------------------------------------------------

test('wraps a privileged command with cwd, sudo flags, and shell quoting', () => {
  const wrapped = wrapPrivilegedCommand('systemctl restart nginx', "/srv/app with space", { mode: 'nopasswd' })
  assert.equal(wrapped, `cd -- '/srv/app with space' && sudo -n -H -p "" -- sh -c 'systemctl restart nginx'`)

  const password = wrapPrivilegedCommand('id', HOME, { mode: 'password', user: 'postgres' })
  assert.equal(password, `cd -- '${HOME}' && sudo -S -k -H -p "" -u 'postgres' -- sh -c 'id'`)

  const root = wrapPrivilegedCommand('echo hi', HOME, { mode: 'nopasswd', user: 'root' })
  assert.equal(root, `cd -- '${HOME}' && sudo -n -H -p "" -- sh -c 'echo hi'`)
})

// ---------------------------------------------------------------------------
// Privilege resolution
// ---------------------------------------------------------------------------

test('resolvePrivilege returns undefined for unprivileged commands', async () => {
  const deps = await fakeDeps(UNKNOWN)
  assert.equal(await resolvePrivilege(deps, makeHost(), { privileged: false }), undefined)
})

test('resolvePrivilege uses nopasswd without touching the credential store', async () => {
  const deps = await fakeDeps(UNKNOWN)
  const host = makeHost({ sudo: { mode: 'nopasswd', user: 'deploy', passwordRef: 'host:host_11111111:sudo' } })
  const privilege = await resolvePrivilege(deps, host, { privileged: true })
  assert.deepEqual(privilege, { mode: 'nopasswd', user: 'deploy' })
})

test('resolvePrivilege resolves the stored sudo password and registers it for redaction', async () => {
  const deps = await fakeDeps(UNKNOWN)
  const host = makeHost({ sudo: { mode: 'password', passwordRef: 'host:host_11111111:sudo' } })
  await deps.secrets.set('host:host_11111111:sudo', 'sudo-secret-value')
  const privilege = await resolvePrivilege(deps, host, { privileged: true })
  assert.deepEqual(privilege, { mode: 'password', password: 'sudo-secret-value' })
  assert.equal(sudoSecretRef(host), 'host:host_11111111:sudo')
  assert.equal(await sudoPasswordStatus(deps, host), 'available')
})

test('password mode falls back to the SSH login password', async () => {
  const deps = await fakeDeps(UNKNOWN)
  const host = makeHost({ sudo: { mode: 'password', passwordRef: 'host:host_11111111:sudo' } })
  await deps.secrets.set(host.auth.type === 'password' ? host.auth.secretRef : '', 'login-secret')
  const privilege = await resolvePrivilege(deps, host, { privileged: true })
  assert.equal(privilege?.mode, 'password')
  assert.equal(privilege?.password, 'login-secret')
})

test('resolvePrivilege reports an unconfigured host, a locked user, and a missing password', async () => {
  const deps = await fakeDeps(UNKNOWN)
  await assert.rejects(
    () => resolvePrivilege(deps, makeHost(), { privileged: true }),
    (error: unknown) => error instanceof SshHostsError && error.code === 'SUDO_NOT_CONFIGURED',
  )
  const locked = makeHost({ sudo: { mode: 'nopasswd', user: 'postgres' } })
  await assert.rejects(
    () => resolvePrivilege(deps, locked, { privileged: true, user: 'root' }),
    (error: unknown) => error instanceof SshHostsError && error.code === 'SUDO_USER_LOCKED',
  )
  const keyed = makeHost({
    auth: { type: 'key', privateKeyPath: '/home/deploy/.ssh/id_ed25519' },
    sudo: { mode: 'password', passwordRef: 'host:host_11111111:sudo' },
  })
  await assert.rejects(
    () => resolvePrivilege(deps, keyed, { privileged: true }),
    (error: unknown) => error instanceof SshHostsError && error.code === 'SUDO_PASSWORD_MISSING',
  )
})
