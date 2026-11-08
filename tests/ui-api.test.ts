import assert from 'node:assert/strict'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { Readable } from 'node:stream'
import test from 'node:test'
import { AuditLog } from '../src/audit.js'
import { withDefaults } from '../src/config.js'
import { HostStore } from '../src/hosts.js'
import { SecretStore } from '../src/secrets.js'
import type { HostRecord, TestResult } from '../src/types.js'
import { createHostsUiHandler, type HostsUiOptions } from '../src/ui-api.js'
import { tempDir } from './helpers.js'

interface FakeRequestInit {
  remoteAddress?: string
  headers?: Record<string, string>
}

function fakeRequest(method: string, url: string, body?: unknown, init: FakeRequestInit = {}): IncomingMessage {
  const stream = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))])
  return Object.assign(stream, {
    method,
    url,
    headers: {
      host: '127.0.0.1:64289',
      'x-ssh-hosts-ui': '1',
      'content-type': 'application/json',
      ...init.headers,
    },
    socket: { remoteAddress: init.remoteAddress ?? '127.0.0.1' },
  }) as unknown as IncomingMessage
}

function fakeResponse() {
  const state = { status: 0, body: '' }
  const res = {
    writeHead(status: number) {
      state.status = status
      return res
    },
    end(text?: string) {
      state.body = text ?? ''
    },
  }
  return { state, res: res as unknown as ServerResponse }
}

async function call(handler: ReturnType<typeof createHostsUiHandler>, req: IncomingMessage) {
  const { state, res } = fakeResponse()
  await handler(req, res)
  return {
    status: state.status,
    text: state.body,
    json: state.body.length === 0 ? null : (JSON.parse(state.body) as Record<string, unknown>),
  }
}

function harness(dir: string) {
  const store = new HostStore(dir)
  const secrets = new SecretStore({ dir, backend: 'file', envPrefix: 'SSH_HOST_' })
  const audit = new AuditLog(dir, true)
  const config = withDefaults({ dataDir: dir, secretsBackend: 'file' })
  const manager = {
    async test(host: HostRecord): Promise<TestResult> {
      return {
        server: host.alias,
        reachable: true,
        authOk: true,
        hostKeyFingerprint: 'SHA256:test',
        hostKeyStatus: 'matched',
        banner: null,
        homeDir: '/home/deploy',
        durationMs: 12,
        error: null,
      }
    },
  }
  const options: HostsUiOptions = {
    dataDir: dir,
    config,
    store,
    secrets,
    manager: manager as unknown as HostsUiOptions['manager'],
    audit,
    debug: () => undefined,
  }
  return { handler: createHostsUiHandler(options), store, secrets, audit }
}

test('management API creates, lists, edits, tests, and removes a host', async () => {
  const dir = await tempDir()
  const { handler, store, secrets } = harness(dir)

  const created = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'web-1',
      host: '10.0.0.10',
      port: 22,
      username: 'deploy',
      authType: 'password',
      password: 'super-secret-pass',
      fingerprintPolicy: 'accept-new',
      allowedPaths: ['~', '~/app'],
      editablePaths: ['~/app'],
      services: [{ name: 'api', directory: '~/app', port: 8080 }],
    }),
  )
  assert.equal(created.status, 201)
  const createdHost = (created.json?.host as Record<string, unknown>)
  assert.equal(createdHost.alias, 'web-1')
  assert.equal(createdHost.credentialStatus, 'available')
  assert.equal(createdHost.port, 22)
  assert.ok(!created.text.includes('super-secret-pass'))
  const id = createdHost.id as string

  const listed = await call(handler, fakeRequest('GET', '/ssh-hosts-ui/hosts'))
  assert.equal(listed.status, 200)
  assert.equal(listed.json?.count, 1)

  const updated = await call(
    handler,
    fakeRequest('PATCH', `/ssh-hosts-ui/hosts/${id}`, {
      alias: 'web-primary',
      host: '10.0.0.11',
      port: 2222,
      username: 'deploy2',
      editablePaths: ['/srv/app'],
      password: 'second-secret',
    }),
  )
  assert.equal(updated.status, 200)
  const updatedHost = updated.json?.host as Record<string, unknown>
  assert.equal(updatedHost.alias, 'web-primary')
  assert.equal(updatedHost.port, 2222)
  assert.deepEqual(updatedHost.editablePaths, ['/srv/app'])
  assert.equal(await store.find('web-primary').then((host) => host.id), id)
  assert.equal(await secrets.get(`host:${id}:password`), 'second-secret')

  const tested = await call(handler, fakeRequest('POST', `/ssh-hosts-ui/hosts/${id}/test`))
  assert.equal(tested.status, 200)
  assert.equal(tested.json?.authOk, true)
  assert.equal(tested.json?.homeDir, '/home/deploy')

  const cleared = await call(handler, fakeRequest('DELETE', `/ssh-hosts-ui/hosts/${id}/credential?kind=password`))
  assert.equal(cleared.status, 200)
  assert.equal(cleared.json?.deleted, 1)
  assert.equal(await secrets.status(`host:${id}:password`), 'missing')

  const removed = await call(handler, fakeRequest('DELETE', `/ssh-hosts-ui/hosts/${id}`))
  assert.equal(removed.status, 200)
  assert.equal(removed.json?.removed, true)
  assert.equal((await store.list()).length, 0)
})

test('management API rejects cross-site, non-loopback, and duplicate writes', async () => {
  const dir = await tempDir()
  const { handler } = harness(dir)

  const noHeader = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'a',
      host: '10.0.0.1',
      username: 'u',
      authType: 'password',
    }, { headers: { 'x-ssh-hosts-ui': '' } }),
  )
  assert.equal(noHeader.status, 403)

  const remote = await call(handler, fakeRequest('GET', '/ssh-hosts-ui/hosts', undefined, { remoteAddress: '10.0.0.2' }))
  assert.equal(remote.status, 403)

  const crossSite = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'a',
      host: '10.0.0.1',
      username: 'u',
      authType: 'password',
    }, { headers: { origin: 'https://evil.example' } }),
  )
  assert.equal(crossSite.status, 403)

  const first = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'dup',
      host: '10.0.0.1',
      username: 'u',
      authType: 'password',
    }),
  )
  assert.equal(first.status, 201)
  const second = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'dup',
      host: '10.0.0.2',
      username: 'u',
      authType: 'password',
    }),
  )
  assert.equal(second.status, 409)
  assert.equal((second.json?.error as Record<string, unknown>).code, 'HOST_ALIAS_EXISTS')
})

test('management API validates payloads and never returns a key path', async () => {
  const dir = await tempDir()
  const { handler } = harness(dir)

  const missing = await call(handler, fakeRequest('POST', '/ssh-hosts-ui/hosts', { alias: 'x' }))
  assert.equal(missing.status, 400)

  const badPort = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'x',
      host: '10.0.0.1',
      username: 'u',
      authType: 'password',
      port: '22',
    }),
  )
  assert.equal(badPort.status, 400)

  const keyed = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'keyed',
      host: '10.0.0.3',
      username: 'deploy',
      authType: 'key',
      privateKeyPath: 'C:\\Users\\deploy\\.ssh\\id_ed25519',
    }),
  )
  assert.equal(keyed.status, 201)
  const keyedHost = keyed.json?.host as Record<string, unknown>
  assert.equal(keyedHost.authType, 'key')
  assert.ok(!keyed.text.includes('id_ed25519'))
  assert.ok(!keyed.text.includes('C:\\\\Users\\\\deploy'))
})

test('management API stores, switches, and clears the sudo policy and password', async () => {
  const dir = await tempDir()
  const { handler, store, secrets } = harness(dir)

  const created = await call(
    handler,
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'sudo-host',
      host: '10.0.0.40',
      username: 'deploy',
      authType: 'password',
      password: 'ssh-pass',
      sudo: { mode: 'password', user: 'root', password: 'sudo-pass' },
    }),
  )
  assert.equal(created.status, 201)
  const host = created.json?.host as Record<string, unknown>
  assert.deepEqual(host.sudo, { mode: 'password', user: 'root', passwordConfigured: true })
  assert.ok(!created.text.includes('sudo-pass'))
  assert.equal(await secrets.get(`host:${host.id as string}:sudo`), 'sudo-pass')

  const patched = await call(
    handler,
    fakeRequest('PATCH', `/ssh-hosts-ui/hosts/${host.id as string}`, { sudo: { mode: 'nopasswd' } }),
  )
  assert.equal(patched.status, 200)
  assert.equal(((patched.json?.host as Record<string, unknown>).sudo as Record<string, unknown>).mode, 'nopasswd')
  assert.equal(await secrets.status(`host:${host.id as string}:sudo`), 'missing', 'switching to NOPASSWD drops the password')

  const rejected = await call(
    handler,
    fakeRequest('PUT', `/ssh-hosts-ui/hosts/${host.id as string}/credential`, { kind: 'sudo', value: 'x' }),
  )
  assert.equal(rejected.status, 400)
  assert.equal((rejected.json?.error as Record<string, unknown>).code, 'INVALID_SUDO')

  const back = await call(
    handler,
    fakeRequest('PATCH', `/ssh-hosts-ui/hosts/${host.id as string}`, { sudo: { mode: 'password', user: 'postgres' } }),
  )
  assert.equal(back.status, 200)
  assert.deepEqual((back.json?.host as Record<string, unknown>).sudo, {
    mode: 'password',
    user: 'postgres',
    // The SSH login password is a documented fallback for sudo in password mode.
    passwordConfigured: true,
  })

  const put = await call(
    handler,
    fakeRequest('PUT', `/ssh-hosts-ui/hosts/${host.id as string}/credential`, { kind: 'sudo', value: 'new-sudo' }),
  )
  assert.equal(put.status, 200)
  assert.equal(await secrets.get(`host:${host.id as string}:sudo`), 'new-sudo')

  const badPayload = await call(
    handler,
    fakeRequest('PATCH', `/ssh-hosts-ui/hosts/${host.id as string}`, {
      sudo: { mode: 'nopasswd', password: 'nope' },
    }),
  )
  assert.equal(badPayload.status, 400)
  assert.equal((badPayload.json?.error as Record<string, unknown>).code, 'INVALID_SUDO')

  const cleared = await call(
    handler,
    fakeRequest('DELETE', `/ssh-hosts-ui/hosts/${host.id as string}/credential?kind=sudo`),
  )
  assert.equal(cleared.status, 200)
  assert.equal(cleared.json?.deleted, 1)
  assert.equal(await secrets.status(`host:${host.id as string}:sudo`), 'missing')
  assert.equal((await store.find('sudo-host')).sudo?.mode, 'password')
})

test('management API refuses secrets when the credential backend is env', async () => {
  const dir = await tempDir()
  const store = new HostStore(dir)
  const secrets = new SecretStore({ dir, backend: 'env', envPrefix: 'SSH_HOST_' })
  const options: HostsUiOptions = {
    dataDir: dir,
    config: withDefaults({ dataDir: dir, secretsBackend: 'env' }),
    store,
    secrets,
    manager: { test: async () => ({}) } as unknown as HostsUiOptions['manager'],
    audit: new AuditLog(dir, false),
    debug: () => undefined,
  }
  const response = await call(
    createHostsUiHandler(options),
    fakeRequest('POST', '/ssh-hosts-ui/hosts', {
      alias: 'env-host',
      host: '10.0.0.4',
      username: 'u',
      authType: 'password',
      password: 'nope',
    }),
  )
  assert.equal(response.status, 400)
  assert.equal((response.json?.error as Record<string, unknown>).code, 'SECRET_ENV_READONLY')
  assert.equal((await store.list()).length, 0)
})
