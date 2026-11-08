import assert from 'node:assert/strict'
import test from 'node:test'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolDefinition, ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { ApprovalOutcome, ApprovalRequest } from '../src/deps.js'
import { HostStore } from '../src/hosts.js'
import { apply } from '../src/index.js'
import { tempDir } from './helpers.js'

interface RecordedAsk {
  toolName: string
  callId?: string
  reason?: string
  displayReason?: { readonly en: string; readonly [locale: string]: string }
}

interface FakeApproval {
  request(request: ApprovalRequest): Promise<ApprovalOutcome>
  effectivePolicy(session: unknown): string
}

interface FakeSandbox {
  resolve(request?: { session?: unknown }): { mode: string }
}

interface Harness {
  registered: Map<string, ToolDefinition>
  asks: RecordedAsk[]
  setOutcome(outcome: ApprovalOutcome): void
  /** Simulate the GUI permission preset the session runs under. */
  setPreset(policy: 'ask' | 'never', mode?: 'read-only' | 'workspace-write' | 'danger-full-access'): void
}

function makeHarness(): { ctx: Context; harness: Harness } {
  const registered = new Map<string, ToolDefinition>()
  const asks: RecordedAsk[] = []
  let outcome: ApprovalOutcome = 'allowed-once'
  let policy: 'ask' | 'never' = 'ask'
  let mode: 'read-only' | 'workspace-write' | 'danger-full-access' = 'workspace-write'
  const approval: FakeApproval = {
    async request(request) {
      asks.push({
        toolName: request.toolName,
        ...(request.callId === undefined ? {} : { callId: request.callId }),
        ...(request.reason === undefined ? {} : { reason: request.reason }),
        ...(request.displayReason === undefined ? {} : { displayReason: request.displayReason }),
      })
      return outcome
    },
    effectivePolicy() {
      return policy
    },
  }
  const sandbox: FakeSandbox = {
    resolve() {
      return { mode }
    },
  }
  const ctx = {
    tools: {
      register(definition: ToolDefinition) {
        registered.set(definition.name, definition)
        return () => registered.delete(definition.name)
      },
    },
    get(name: string) {
      if (name === 'approval') return approval
      if (name === 'sandboxPolicy') return sandbox
      return undefined
    },
    effect(fn: () => void | (() => void)) {
      const disposer = fn()
      return () => {
        if (typeof disposer === 'function') disposer()
      }
    },
  } as unknown as Context
  return {
    ctx,
    harness: {
      registered,
      asks,
      setOutcome(next: ApprovalOutcome) {
        outcome = next
      },
      setPreset(nextPolicy, nextMode) {
        policy = nextPolicy
        if (nextMode !== undefined) mode = nextMode
      },
    },
  }
}

function execFor(sessionId: string, callId = 'call-1'): ToolRunContext {
  return {
    agent: {
      id: `agent-${sessionId}`,
      session: { id: sessionId, header: { id: sessionId, cwd: process.cwd() } },
    },
    callId,
    signal: new AbortController().signal,
    deferContext() {},
    concludeTurn() {},
  } as unknown as ToolRunContext
}

async function seedTwoHosts(): Promise<string> {
  const dir = await tempDir('dsh-ssh-consent-')
  const store = new HostStore(dir)
  await store.add({ alias: 'alpha', host: '10.0.0.1', username: 'deploy', authType: 'password' })
  await store.add({ alias: 'beta', host: '10.0.0.2', username: 'deploy', authType: 'password' })
  return dir
}

test('asks once per session and per server, and never reuses a grant across servers', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  apply(ctx, { dataDir: dir, sessionConsent: 'ask' })

  const list = harness.registered.get('ssh_host_list')
  const update = harness.registered.get('ssh_host_update')
  assert.ok(list !== undefined && update !== undefined)

  // Host inventory is its own scope: one prompt per session, not per host.
  const listed = (await list.execute({}, execFor('session-a'))) as { count: number }
  assert.equal(listed.count, 2)
  assert.equal(harness.asks.length, 1)
  assert.match(harness.asks[0]?.displayReason?.zh ?? '', /主机清单/)
  await list.execute({}, execFor('session-a'))
  assert.equal(harness.asks.length, 1)

  // Server alpha: first use asks, the second use does not.
  await update.execute({ server: 'alpha', note: 'first' }, execFor('session-a'))
  assert.equal(harness.asks.length, 2)
  assert.match(harness.asks[1]?.displayReason?.zh ?? '', /alpha/)
  await update.execute({ server: 'alpha', note: 'second' }, execFor('session-a'))
  assert.equal(harness.asks.length, 2)

  // A different server needs its own approval, even in the same session.
  await update.execute({ server: 'beta', note: 'beta' }, execFor('session-a'))
  assert.equal(harness.asks.length, 3)
  assert.match(harness.asks[2]?.displayReason?.zh ?? '', /beta/)

  // A new session starts with no grants, including for a server used earlier.
  await update.execute({ server: 'alpha', note: 'new session' }, execFor('session-b'))
  assert.equal(harness.asks.length, 4)
})

test('inventory viewing and adding are separate consents', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  apply(ctx, { dataDir: dir, sessionConsent: 'ask' })
  const list = harness.registered.get('ssh_host_list')
  const add = harness.registered.get('ssh_host_add')
  assert.ok(list !== undefined && add !== undefined)

  await list.execute({}, execFor('session-a'))
  assert.equal(harness.asks.length, 1)

  // Viewing the list must not silently grant permission to add a server.
  await add.execute({ alias: 'gamma', host: '10.0.0.3', username: 'deploy', authType: 'password' }, execFor('session-a'))
  assert.equal(harness.asks.length, 2)
  assert.match(harness.asks[1]?.displayReason?.zh ?? '', /新增 SSH 主机/)

  // Both grants are now remembered for this session.
  await list.execute({}, execFor('session-a'))
  assert.equal(harness.asks.length, 2)
})

test('a denial blocks that call but a later explicit retry asks again', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  apply(ctx, { dataDir: dir, sessionConsent: 'ask' })
  const update = harness.registered.get('ssh_host_update')
  assert.ok(update !== undefined)

  harness.setOutcome('rejected')
  await assert.rejects(
    () => update.execute({ server: 'alpha', note: 'no' }, execFor('session-a')),
    (error: unknown) =>
      error instanceof Error && /SESSION_CONSENT_DENIED/.test(error.message) && /alpha/.test(error.message),
  )
  assert.equal(harness.asks.length, 1)

  // Changing one's mind must not require a new session.
  harness.setOutcome('allowed-once')
  await update.execute({ server: 'alpha', note: 'yes' }, execFor('session-a'))
  assert.equal(harness.asks.length, 2)
})

test('an unknown server is left to the tool error instead of prompting', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  apply(ctx, { dataDir: dir, sessionConsent: 'ask' })
  const update = harness.registered.get('ssh_host_update')
  assert.ok(update !== undefined)

  await assert.rejects(
    () => update.execute({ server: 'ghost', note: 'x' }, execFor('session-a')),
    (error: unknown) => error instanceof Error && /HOST_NOT_FOUND/.test(error.message),
  )
  assert.equal(harness.asks.length, 0)
})

test('sessionConsent=allow keeps the old unconditional behaviour', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  apply(ctx, { dataDir: dir, sessionConsent: 'allow' })
  const update = harness.registered.get('ssh_host_update')
  assert.ok(update !== undefined)

  await update.execute({ server: 'alpha', note: 'a' }, execFor('session-a'))
  await update.execute({ server: 'beta', note: 'b' }, execFor('session-a'))
  assert.equal(harness.asks.length, 0)
})

test('sessionConsent=deny blocks every tool without asking', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  apply(ctx, { dataDir: dir, sessionConsent: 'deny' })
  const list = harness.registered.get('ssh_host_list')
  assert.ok(list !== undefined)

  await assert.rejects(
    () => list.execute({}, execFor('session-a')),
    (error: unknown) => error instanceof Error && /sessionConsent=deny/.test(error.message),
  )
  assert.equal(harness.asks.length, 0)
})

test('「完全权限」 sessions grant server consent without prompting', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  harness.setPreset('never', 'danger-full-access')
  apply(ctx, { dataDir: dir, sessionConsent: 'ask' })
  const update = harness.registered.get('ssh_host_update')
  assert.ok(update !== undefined)

  // A `never` approval policy cannot show a prompt at all; the gate records a
  // process-local grant so the plugin stays usable in that preset.
  await update.execute({ server: 'alpha', note: 'full access' }, execFor('session-a'))
  assert.equal(harness.asks.length, 0)
  await update.execute({ server: 'beta', note: 'other server' }, execFor('session-a'))
  assert.equal(harness.asks.length, 0)
})

test('a no-prompt session with a restricted sandbox still skips the consent prompt', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  harness.setPreset('never', 'workspace-write')
  apply(ctx, { dataDir: dir, sessionConsent: 'ask' })
  const list = harness.registered.get('ssh_host_list')
  assert.ok(list !== undefined)

  const listed = (await list.execute({}, execFor('session-a'))) as { count: number }
  assert.equal(listed.count, 2)
  assert.equal(harness.asks.length, 0)
})

test('trustFullAccess=false keeps the old fail-closed consent behaviour', async () => {
  const dir = await seedTwoHosts()
  const { ctx, harness } = makeHarness()
  harness.setPreset('never', 'danger-full-access')
  harness.setOutcome('rejected')
  apply(ctx, { dataDir: dir, sessionConsent: 'ask', trustFullAccess: false })
  const update = harness.registered.get('ssh_host_update')
  assert.ok(update !== undefined)

  await assert.rejects(
    () => update.execute({ server: 'alpha', note: 'x' }, execFor('session-a')),
    (error: unknown) => error instanceof Error && /SESSION_CONSENT_DENIED/.test(error.message),
  )
  assert.equal(harness.asks.length, 1)
})
