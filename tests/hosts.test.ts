import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { HostStore, toHostView } from '../src/hosts.js'
import { tempDir } from './helpers.js'

test('adds, lists, updates, removes, and persists hosts', async () => {
  const dir = await tempDir()
  const store = new HostStore(dir)
  const added = await store.add({
    alias: 'web-1',
    host: '10.0.0.10',
    username: 'deploy',
    authType: 'password',
    fingerprintPolicy: 'accept-new',
    allowedPaths: ['~/app', '/tmp'],
    editablePaths: ['~/app'],
    services: [{ name: 'api', directory: '~/app', description: 'backend API', port: 8080 }],
    tags: ['prod'],
  })
  assert.match(added.id, /^host_[0-9a-f]{8}$/)
  assert.deepEqual(added.editablePaths, ['~/app'])
  assert.equal(added.services[0]?.name, 'api')
  assert.equal((await store.list()).length, 1)

  const byAlias = await store.find('web-1')
  assert.equal(byAlias.id, added.id)

  const updated = await store.update('web-1', { alias: 'web-primary' })
  assert.equal(updated.alias, 'web-primary')
  assert.equal(updated.port, 22)
  await assert.rejects(() => store.update('web-primary', { port: 2222 }), /HOST_IDENTITY_LOCKED/)
  await assert.rejects(() => store.update('web-primary', { allowedPaths: ['/'] }), /PATH_POLICY_LOCKED/)
  await assert.rejects(() => store.update('web-primary', { editablePaths: ['/'] }), /EDIT_POLICY_LOCKED/)
  const withServices = await store.update('web-primary', {
    services: [
      { name: 'api', directory: '~/app', description: 'backend API' },
      { name: 'worker', directory: '~/app/worker' },
    ],
  })
  assert.equal(withServices.services.length, 2)
  assert.equal(withServices.services[1]?.name, 'worker')
  await assert.rejects(() => store.find('web-1'), /未找到主机/)

  await store.setFingerprint(added.id, 'SHA256:abc')
  assert.equal((await store.find('web-primary')).fingerprint?.sha256, 'SHA256:abc')

  const removed = await store.remove('web-primary')
  assert.equal(removed.id, added.id)
  assert.equal((await store.list()).length, 0)

  const raw = await readFile(join(dir, 'hosts.json'), 'utf8')
  assert.ok(raw.includes('"version": 1'))
  assert.ok(!raw.includes('"password":'))
})

test('managed updates may change locked fields and clear stale fingerprints', async () => {
  const store = new HostStore(await tempDir())
  const host = await store.add({
    alias: 'managed',
    host: '10.0.0.20',
    username: 'deploy',
    authType: 'key',
    privateKeyPath: '/home/deploy/.ssh/id_ed25519',
    fingerprintPolicy: 'accept-new',
  })
  await store.setFingerprint(host.id, 'SHA256:old')

  const renamed = await store.updateManaged(host.id, { alias: 'managed-2' })
  assert.equal(renamed.alias, 'managed-2')
  assert.equal(renamed.fingerprint?.sha256, 'SHA256:old', 'alias-only edit keeps the fingerprint')

  const moved = await store.updateManaged(host.id, { host: '10.0.0.21', port: 2222, username: 'root' })
  assert.equal(moved.host, '10.0.0.21')
  assert.equal(moved.port, 2222)
  assert.equal(moved.username, 'root')
  assert.equal(moved.fingerprint, null, 'identity change clears the old TOFU fingerprint')

  const pinned = await store.updateManaged(host.id, {
    hostKeyFingerprint: 'SHA256:0vWs8CTSK4QhmC89cDzYnAP+fWsaXDLwEYjKtUriUgc',
  })
  assert.equal(pinned.fingerprint?.sha256, 'SHA256:0vWs8CTSK4QhmC89cDzYnAP+fWsaXDLwEYjKtUriUgc')

  const policied = await store.updateManaged(host.id, { allowedPaths: ['~/app'], editablePaths: ['/srv/app'], readOnly: true })
  assert.deepEqual(policied.allowedPaths, ['~/app'])
  assert.deepEqual(policied.editablePaths, ['/srv/app'])
  assert.equal(policied.readOnly, true)
  await assert.rejects(() => store.updateManaged(host.id, { allowedPaths: [] }), /allowedPaths 不能为空/)
  await assert.rejects(() => store.updateManaged(host.id, { authType: 'password', privateKeyPath: '/tmp/key' }), /密码认证不能设置/)
  await assert.rejects(() => store.updateManaged(host.id, { hostKeyFingerprint: 'nope' }), /INVALID_FINGERPRINT/)
})

test('accepts a pre-trusted SHA256 host-key fingerprint', async () => {
  const store = new HostStore(await tempDir())
  const host = await store.add({
    alias: 'pinned',
    host: '10.0.0.11',
    username: 'deploy',
    authType: 'password',
    hostKeyFingerprint: 'SHA256:0vWs8CTSK4QhmC89cDzYnAP+fWsaXDLwEYjKtUriUgc',
  })
  assert.equal(host.fingerprint?.sha256, 'SHA256:0vWs8CTSK4QhmC89cDzYnAP+fWsaXDLwEYjKtUriUgc')
  assert.equal(host.fingerprintPolicy, 'strict')
  await assert.rejects(
    () => store.add({ alias: 'bad-fp', host: '10.0.0.12', username: 'deploy', authType: 'password', hostKeyFingerprint: 'nope' }),
    /INVALID_FINGERPRINT/,
  )
})

test('rejects duplicate aliases instead of silently overwriting', async () => {
  const store = new HostStore(await tempDir())
  await store.add({ alias: 'api', host: '10.0.0.1', username: 'deploy', authType: 'password' })
  await assert.rejects(
    () => store.add({ alias: 'api', host: '10.0.0.2', username: 'deploy', authType: 'password' }),
    /HOST_ALIAS_EXISTS|别名已存在/,
  )
  await store.add({ alias: 'db', host: '10.0.0.3', username: 'deploy', authType: 'password' })
  await assert.rejects(() => store.update('db', { alias: 'api' }), /别名已存在/)
})

test('rejects invalid ports, names, and key auth without a key path', async () => {
  const store = new HostStore(await tempDir())
  await assert.rejects(() => store.add({ alias: 'x', host: 'h', username: 'u', authType: 'password', port: 0 }), /端口无效/)
  await assert.rejects(() => store.add({ alias: 'bad alias', host: 'h', username: 'u', authType: 'password' }), /别名无效/)
  await assert.rejects(() => store.add({ alias: 'x', host: 'has space', username: 'u', authType: 'password' }), /主机名无效/)
  await assert.rejects(() => store.add({ alias: 'x', host: 'h', username: 'u', authType: 'key' }), /privateKeyPath/)
})

test('persists the user-managed sudo policy and locks it against the model tool', async () => {
  const dir = await tempDir()
  const store = new HostStore(dir)
  const host = await store.add({
    alias: 'sudo-1',
    host: '10.0.0.31',
    username: 'deploy',
    authType: 'password',
    sudo: { mode: 'password', user: 'root' },
  })
  assert.equal(host.sudo?.mode, 'password')
  assert.equal(host.sudo?.passwordRef, `host:${host.id}:sudo`)

  const view = toHostView(host, 'available', true)
  assert.deepEqual(view.sudo, { mode: 'password', user: 'root', passwordConfigured: true })
  const withoutPassword = toHostView(host, 'available', false)
  assert.equal(withoutPassword.sudo.passwordConfigured, false)

  await assert.rejects(() => store.update(host.id, { sudo: { mode: 'nopasswd' } }), /SUDO_POLICY_LOCKED/)
  const unchanged = await store.update(host.id, { sudo: { mode: 'password', user: 'root' } })
  assert.equal(unchanged.sudo?.mode, 'password', 'passing the current policy back is a no-op')

  const managed = await store.updateManaged(host.id, { sudo: { mode: 'nopasswd', user: 'postgres' } })
  assert.equal(managed.sudo?.mode, 'nopasswd')
  assert.equal(managed.sudo?.user, 'postgres')

  const reloaded = await new HostStore(dir).load()
  assert.equal(reloaded[0]?.sudo?.mode, 'nopasswd')
  assert.equal(reloaded[0]?.sudo?.user, 'postgres')

  const cleared = await store.updateManaged(host.id, { sudo: { mode: 'off' } })
  assert.equal(cleared.sudo, undefined)
  await assert.rejects(
    () => store.updateManaged(host.id, { sudo: { mode: 'password', user: 'bad user' } }),
    /INVALID_SUDO/,
  )
})

test('rejects a malformed sudo block in hosts.json', async () => {
  const dir = await tempDir()
  const record = {
    id: 'host_00000003',
    alias: 'bad-sudo',
    host: '10.0.0.32',
    port: 22,
    username: 'u',
    auth: { type: 'password', secretRef: 'host:host_00000003:password' },
    fingerprint: null,
    fingerprintPolicy: 'strict',
    allowedPaths: ['~'],
    deniedPaths: [],
    sudo: { mode: 'root' },
    readOnly: false,
    tags: [],
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString(),
  }
  await writeFile(join(dir, 'hosts.json'), JSON.stringify({ version: 1, hosts: [record] }), 'utf8')
  await assert.rejects(() => new HostStore(dir).load(), /sudo\.mode 无效/)
})

test('redacted views never expose the private-key path', async () => {
  const store = new HostStore(await tempDir())
  const host = await store.add({
    alias: 'keyed',
    host: '10.0.0.9',
    username: 'deploy',
    authType: 'key',
    privateKeyPath: 'C:\\Users\\deploy\\.ssh\\id_ed25519',
  })
  const view = toHostView(host, 'available')
  const serialized = JSON.stringify(view)
  assert.ok(!serialized.includes('id_ed25519'))
  assert.ok(!serialized.includes('privateKeyPath'))
  assert.equal(view.privateKeyConfigured, true)
  assert.equal(view.authType, 'key')
})

test('reports malformed hosts.json with the file path', async () => {
  const dir = await tempDir()
  await writeFile(join(dir, 'hosts.json'), '{ not json', 'utf8')
  const store = new HostStore(dir)
  await assert.rejects(() => store.load(), /配置文件不是合法 JSON/)
})

test('rejects duplicate aliases loaded from disk', async () => {
  const dir = await tempDir()
  const record = {
    id: 'host_00000001',
    alias: 'dup',
    host: '10.0.0.1',
    port: 22,
    username: 'u',
    auth: { type: 'password', secretRef: 'host:host_00000001:password' },
    fingerprint: null,
    fingerprintPolicy: 'strict',
    allowedPaths: ['~'],
    deniedPaths: [],
    readOnly: false,
    tags: [],
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString(),
  }
  await writeFile(
    join(dir, 'hosts.json'),
    JSON.stringify({ version: 1, hosts: [record, { ...record, id: 'host_00000002' }] }),
    'utf8',
  )
  const store = new HostStore(dir)
  await assert.rejects(() => store.load(), /重复别名/)
})
