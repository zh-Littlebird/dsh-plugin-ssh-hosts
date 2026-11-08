import assert from 'node:assert/strict'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { Readable } from 'node:stream'
import test from 'node:test'
import type { Context } from '@deepseek-ai/cordis'
import { apply } from '../src/index.js'
import { AuditLog } from '../src/audit.js'
import { HostStore } from '../src/hosts.js'
import type { WebRouteLike } from '../src/web.js'
import { tempDir } from './helpers.js'

function fakeRequest(method: string, url: string): IncomingMessage {
  return Object.assign(Readable.from([]), {
    method,
    url,
    headers: { host: '127.0.0.1:64289', 'x-ssh-hosts-ui': '1' },
    socket: { remoteAddress: '127.0.0.1' },
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

test('apply mounts the history and management routes', async () => {
  const dir = await tempDir()
  const routes: WebRouteLike[] = []
  const webServer = {
    register(route: WebRouteLike) {
      routes.push(route)
      return () => undefined
    },
  }
  const tools = new Map<string, unknown>()
  const ctx = {
    tools: {
      register(definition: { name: string }) {
        tools.set(definition.name, definition)
        return () => undefined
      },
    },
    get(name: string) {
      return name === 'webServer' ? webServer : undefined
    },
    effect(fn: () => unknown) {
      const disposer = fn()
      return () => {
        if (typeof disposer === 'function') (disposer as () => void)()
      }
    },
    inject(_deps: string[], execute: (inner: unknown) => unknown) {
      execute(ctx)
    },
  } as unknown as Context

  apply(ctx, { dataDir: dir, audit: true, sessionConsent: 'allow' })
  assert.ok(tools.has('ssh_exec'))
  assert.deepEqual(
    routes.map((route) => route.path).sort(),
    ['/ssh-hosts-api', '/ssh-hosts-ui'],
  )

  const store = new HostStore(dir)
  const host = await store.add({ alias: 'wired', host: '10.0.0.1', username: 'root', authType: 'password' })
  await new AuditLog(dir, true).append({
    action: 'exec',
    server: 'wired',
    hostId: host.id,
    user: 'root',
    command: 'true',
    exitCode: 0,
    ok: true,
  })

  const uiRoute = routes.find((route) => route.path === '/ssh-hosts-ui')
  assert.ok(uiRoute)
  const ui = fakeResponse()
  await uiRoute.handler(fakeRequest('GET', '/ssh-hosts-ui/hosts'), ui.res)
  assert.equal(ui.state.status, 200)
  const uiBody = JSON.parse(ui.state.body) as Record<string, unknown>
  assert.equal(uiBody.count, 1)

  const historyRoute = routes.find((route) => route.path === '/ssh-hosts-api')
  assert.ok(historyRoute)
  const history = fakeResponse()
  await historyRoute.handler(fakeRequest('GET', '/ssh-hosts-api/history'), history.res)
  assert.equal(history.state.status, 200)
  const historyBody = JSON.parse(history.state.body) as {
    servers: Array<{ id: string; ip: string; count: number; aliases: string[] }>
    entries: Array<{ serverId?: string }>
  }
  assert.equal(historyBody.servers.length, 1)
  assert.equal(historyBody.servers[0]?.ip, '10.0.0.1')
  assert.equal(historyBody.servers[0]?.id, 'ip:10.0.0.1')
  assert.deepEqual(historyBody.servers[0]?.aliases, ['wired'])
  assert.equal(historyBody.entries[0]?.serverId, 'ip:10.0.0.1')
})
