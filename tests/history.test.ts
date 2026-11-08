import assert from 'node:assert/strict'
import { rm } from 'node:fs/promises'
import test from 'node:test'
import { AuditLog } from '../src/audit.js'
import { HostStore } from '../src/hosts.js'
import { readHistory } from '../src/history.js'
import { tempDir } from './helpers.js'

test('history keeps one server row across renames and hides inventory events', async () => {
  const dir = await tempDir()
  const store = new HostStore(dir)
  const audit = new AuditLog(dir, true)
  const host = await store.add({
    alias: 'old-name',
    host: '10.0.0.10',
    username: 'root',
    authType: 'password',
  })

  await audit.append({
    action: 'exec',
    server: 'old-name',
    hostId: host.id,
    user: 'root',
    command: 'uname -a',
    exitCode: 0,
    ok: true,
  })
  await audit.append({ action: 'host_update', server: 'new-name', hostId: host.id, user: 'root', ok: true })
  await store.updateManaged(host.id, { alias: 'new-name' })
  await audit.append({
    action: 'exec',
    server: 'new-name',
    hostId: host.id,
    user: 'root',
    command: 'pwd',
    exitCode: 0,
    ok: true,
  })
  // A record from the pre-hostId version keeps its historical alias.
  await audit.append({ action: 'exec', server: 'legacy', user: 'root', command: 'old-command', exitCode: 0, ok: true })
  // An address-shaped legacy alias (the old `ssh-<dashed-ip>` convention) is
  // folded into the current host for the same IP.
  await audit.append({ action: 'exec', server: 'ssh-10-0-0-10', user: 'root', command: 'legacy-ip', exitCode: 0, ok: true })

  const hosts = await store.list()
  const page = await readHistory(dir, {}, true, hosts)
  assert.equal(page.total, 4, 'host_update is not command history')
  assert.equal(page.servers.length, 1, 'one address row, however many aliases')
  assert.equal(page.servers[0]?.ip, '10.0.0.10')
  assert.equal(page.servers[0]?.id, 'ip:10.0.0.10')
  assert.deepEqual(page.servers[0]?.aliases, ['new-name'])
  assert.equal(page.servers[0]?.count, 3)

  const commands = page.entries.map((entry) => entry.command).sort()
  assert.deepEqual(commands, ['legacy-ip', 'old-command', 'pwd', 'uname -a'].sort())
  const renamed = page.entries.find((entry) => entry.command === 'uname -a')
  assert.equal(renamed?.server, 'new-name', 'the historical alias is still available for display')
  assert.equal(renamed?.serverIp, '10.0.0.10', 'rows are grouped by address')
  assert.equal(renamed?.serverId, 'ip:10.0.0.10')
  const legacyIp = page.entries.find((entry) => entry.command === 'legacy-ip')
  assert.equal(legacyIp?.serverIp, '10.0.0.10', 'address-shaped legacy alias resolves too')
  const legacy = page.entries.find((entry) => entry.command === 'old-command')
  assert.equal(legacy?.server, 'legacy')
  assert.equal(legacy?.serverId, undefined)

  for (const query of [host.id, 'old-name', '10.0.0.10', 'ip:10.0.0.10']) {
    const byServer = await readHistory(dir, { server: query }, true, hosts)
    assert.equal(byServer.matched, 3, `server query ${query} targets the same address`)
  }

  await rm(dir, { recursive: true, force: true })
})

test('history groups different hosts that share one IP into a single row', async () => {
  const dir = await tempDir()
  const store = new HostStore(dir)
  const audit = new AuditLog(dir, true)
  const first = await store.add({ alias: 'web-a', host: '10.1.1.5', port: 22, username: 'root', authType: 'password' })
  const second = await store.add({ alias: 'web-b', host: '10.1.1.5', port: 2222, username: 'root', authType: 'password' })

  for (const host of [first, second]) {
    await audit.append({
      action: 'exec',
      server: host.alias,
      hostId: host.id,
      user: 'root',
      command: `echo ${host.alias}`,
      exitCode: 0,
      ok: true,
    })
  }

  const page = await readHistory(dir, {}, true, await store.list())
  assert.equal(page.servers.length, 1)
  assert.equal(page.servers[0]?.ip, '10.1.1.5')
  assert.equal(page.servers[0]?.count, 2)
  assert.deepEqual(page.servers[0]?.aliases.sort(), ['web-a', 'web-b'])
  assert.ok(page.entries.every((entry) => entry.serverIp === '10.1.1.5'))

  await rm(dir, { recursive: true, force: true })
})
