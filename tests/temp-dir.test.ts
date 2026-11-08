import assert from 'node:assert/strict'
import test from 'node:test'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolDefinition, ToolRunContext } from '@deepseek-ai/dsh-tools'
import { configuredTempDir, withDefaults } from '../src/config.js'
import { assertCommandEditsAllowed } from '../src/edits.js'
import { HostStore } from '../src/hosts.js'
import { apply } from '../src/index.js'
import {
  assertRemoteEditable,
  resolveTempRoot,
  tempDirHint,
  withTempRoot,
  type RemotePathPolicy,
} from '../src/paths.js'
import { SshManager } from '../src/ssh.js'
import type { HostRecord } from '../src/types.js'
import { SshHostsError } from '../src/types.js'
import { tempDir } from './helpers.js'

function hostRecord(overrides: Partial<HostRecord> = {}): HostRecord {
  return {
    id: 'host_00000001',
    alias: 'web-1',
    host: '10.0.0.10',
    port: 22,
    username: 'deploy',
    auth: { type: 'password', secretRef: 'host:host_00000001:password' },
    fingerprint: null,
    fingerprintPolicy: 'strict',
    allowedPaths: ['~'],
    editablePaths: [],
    services: [],
    deniedPaths: ['~/.ssh'],
    readOnly: false,
    tags: [],
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString(),
    ...overrides,
  }
}

function manager(tempDir: string): SshManager {
  return new SshManager({
    config: withDefaults({ tempDir }),
    credentials: async () => ({}),
    onFingerprint: async () => undefined,
    debug: () => undefined,
  })
}

test('tempDir defaults to /tmp and can be disabled with an empty string', () => {
  assert.equal(withDefaults(undefined).tempDir, '/tmp')
  assert.equal(withDefaults({}).tempDir, '/tmp')
  assert.equal(configuredTempDir(withDefaults({})), '/tmp')
  assert.equal(withDefaults({ tempDir: '' }).tempDir, '')
  assert.equal(configuredTempDir(withDefaults({ tempDir: '' })), null)
  assert.equal(withDefaults({ tempDir: '  /var/tmp  ' }).tempDir, '/var/tmp')
})

test('expands and folds the scratch directory into one path list', () => {
  assert.equal(resolveTempRoot('/tmp', '/home/deploy'), '/tmp')
  assert.equal(resolveTempRoot('~/tmp', '/home/deploy'), '/home/deploy/tmp')
  assert.equal(resolveTempRoot('', '/home/deploy'), null)
  assert.equal(resolveTempRoot('   ', '/home/deploy'), null)

  assert.deepEqual(withTempRoot(['~'], '/tmp', '/home/deploy', '/home/deploy'), ['~', '/tmp'])
  assert.deepEqual(withTempRoot(['~/app'], '/tmp', '/home/deploy', '/home/deploy'), ['~/app', '/tmp'])
  // A root that already contains the scratch directory is reused, not duplicated.
  assert.deepEqual(withTempRoot(['/'], '/tmp', '/home/deploy', '/home/deploy'), ['/'])
  assert.deepEqual(withTempRoot(['/var'], '/var/tmp', '/home/deploy', '/home/deploy'), ['/var'])
  // Disabled: the stored list is returned unchanged.
  assert.deepEqual(withTempRoot(['~/app'], null, '/home/deploy', '/home/deploy'), ['~/app'])
})

test('the effective policy makes /tmp readable and writable without touching host storage', () => {
  const host = hostRecord()
  const policy = manager('/tmp').policyFor(host, '/home/deploy')
  assert.deepEqual(policy.allowedPaths, ['~', '/tmp'])
  assert.deepEqual(policy.editablePaths, ['/tmp'])
  assert.equal(policy.tempDir, '/tmp')
  assert.deepEqual(host.editablePaths, [], 'the stored host record is never mutated')

  assert.equal(assertRemoteEditable('/tmp/dsh-task/out.txt', policy), '/tmp/dsh-task/out.txt')
  assert.doesNotThrow(() => assertCommandEditsAllowed('echo hi > /tmp/dsh-task/out.txt', { ...policy, cwd: '/tmp' }))
})

test('disabling tempDir restores the per-host policy', () => {
  const host = hostRecord({ editablePaths: ['~/app'] })
  const policy = manager('').policyFor(host, '/home/deploy')
  assert.deepEqual(policy.allowedPaths, ['~'])
  assert.deepEqual(policy.editablePaths, ['~/app'])
  assert.equal(policy.tempDir, null)
  assert.throws(() => assertRemoteEditable('/tmp/out.txt', policy), /REMOTE_PATH_DENIED/)
  assert.equal(tempDirHint(policy), null)
})

test('the scratch grant never overrides deniedPaths', () => {
  const host = hostRecord({ deniedPaths: ['/tmp'] })
  const policy = manager('/tmp').policyFor(host, '/home/deploy')
  assert.equal(policy.tempDir, null, 'a denied scratch directory is not granted nor advertised')
  assert.deepEqual(policy.allowedPaths, ['~'])
  assert.deepEqual(policy.editablePaths, [])
  assert.throws(() => assertRemoteEditable('/tmp/out.txt', policy), /DENIED/)
})

test('write refusals point the model at the scratch directory', () => {
  const policy: RemotePathPolicy = {
    home: '/home/deploy',
    cwd: '/home/deploy',
    allowedPaths: ['~', '/tmp'],
    editablePaths: ['~/app', '/tmp'],
    deniedPaths: ['~/.ssh'],
    tempDir: '/tmp',
  }
  assert.throws(
    () => assertRemoteEditable('/home/deploy/other/x.txt', policy),
    (error: unknown) =>
      error instanceof SshHostsError && error.code === 'EDIT_PATH_DENIED' && /\/tmp/.test(error.hint ?? ''),
  )
  assert.throws(
    () => assertCommandEditsAllowed('rm -f /home/deploy/other/x.txt', { ...policy, cwd: '/home/deploy/app' }),
    (error: unknown) =>
      error instanceof SshHostsError && error.code === 'EDIT_PATH_DENIED' && /\/tmp/.test(error.hint ?? ''),
  )
  // A cwd outside every editable root still names the scratch directory.
  assert.throws(
    () => assertCommandEditsAllowed('touch x', { ...policy, cwd: '/home/deploy' }),
    (error: unknown) => error instanceof SshHostsError && /cwd=\/tmp/.test(error.hint ?? ''),
  )
})

function toolContext(): { ctx: Context; registered: Map<string, ToolDefinition> } {
  const registered = new Map<string, ToolDefinition>()
  const ctx = {
    tools: {
      register(definition: ToolDefinition) {
        registered.set(definition.name, definition)
        return () => registered.delete(definition.name)
      },
    },
    get: () => undefined,
    effect(fn: () => void | (() => void)) {
      const disposer = fn()
      return () => {
        if (typeof disposer === 'function') disposer()
      }
    },
  } as unknown as Context
  return { ctx, registered }
}

function runContext(): ToolRunContext {
  return {
    agent: { id: 'agent-1', session: { id: 'session-1', header: { id: 'session-1', cwd: process.cwd() } } },
    callId: 'call-1',
    signal: new AbortController().signal,
    deferContext() {},
    concludeTurn() {},
  } as unknown as ToolRunContext
}

test('a tool failure keeps its actionable hint in the model-facing message', async () => {
  const dir = await tempDir('dsh-ssh-temp-')
  const store = new HostStore(dir)
  await store.add({ alias: 'web-1', host: '10.0.0.10', username: 'deploy', authType: 'password' })
  const { ctx, registered } = toolContext()
  apply(ctx, { dataDir: dir, sessionConsent: 'allow' })

  const update = registered.get('ssh_host_update')
  assert.ok(update !== undefined)
  await assert.rejects(
    async () => update.execute({ server: 'web-1', editablePaths: ['/'] }, runContext()),
    (error: unknown) =>
      error instanceof Error &&
      /\[EDIT_POLICY_LOCKED\]/.test(error.message) &&
      /请由用户编辑 hosts\.json/.test(error.message),
  )
})
