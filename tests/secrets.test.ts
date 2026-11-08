import assert from 'node:assert/strict'
import { readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { envNameFor, SecretStore } from '../src/secrets.js'
import { tempDir } from './helpers.js'

const REF = 'host:host_abcd1234:password'

test('encrypts credentials at rest and round-trips them', async () => {
  const dir = await tempDir()
  const store = new SecretStore({ dir, backend: 'file', envPrefix: 'SSH_HOST_' })
  assert.equal(await store.status(REF), 'missing')
  await store.set(REF, 'p@ss w0rd!')
  assert.equal(await store.status(REF), 'available')
  assert.equal(await store.get(REF), 'p@ss w0rd!')

  const credentials = await readFile(join(dir, 'credentials.json'), 'utf8')
  assert.ok(!credentials.includes('p@ss w0rd!'))
  assert.ok(credentials.includes('aes-256-gcm') === false)
  assert.ok(credentials.includes('"tag"'))

  const master = await readFile(join(dir, 'master.key'), 'utf8')
  assert.equal(Buffer.from(master.trim(), 'base64').length, 32)
})

test('deletes one host and leaves other hosts alone', async () => {
  const dir = await tempDir()
  const store = new SecretStore({ dir, backend: 'file', envPrefix: 'SSH_HOST_' })
  await store.set('host:host_aaaaaaaa:password', 'a')
  await store.set('host:host_aaaaaaaa:passphrase', 'b')
  await store.set('host:host_bbbbbbbb:password', 'c')
  assert.equal(await store.deleteHost('host_aaaaaaaa'), 2)
  assert.equal(await store.status('host:host_aaaaaaaa:password'), 'missing')
  assert.equal(await store.get('host:host_bbbbbbbb:password'), 'c')
})

test('detects ciphertext tampering', async () => {
  const dir = await tempDir()
  const store = new SecretStore({ dir, backend: 'file', envPrefix: 'SSH_HOST_' })
  await store.set(REF, 'secret-value')
  const file = join(dir, 'credentials.json')
  const document = JSON.parse(await readFile(file, 'utf8')) as { entries: Record<string, { data: string }> }
  const entry = document.entries[REF]
  assert.ok(entry)
  entry.data = `${entry.data.startsWith('A') ? 'B' : 'A'}${entry.data.slice(1)}`
  await writeFile(file, JSON.stringify(document), 'utf8')
  await assert.rejects(() => store.get(REF), /SECRET_DECRYPT_FAILED|解密失败/)
})

test('detects a mismatched master key', async () => {
  const dir = await tempDir()
  const store = new SecretStore({ dir, backend: 'file', envPrefix: 'SSH_HOST_' })
  await store.set(REF, 'secret-value')
  await writeFile(join(dir, 'master.key'), `${Buffer.alloc(32, 7).toString('base64')}\n`, 'utf8')
  await assert.rejects(() => store.get(REF), /SECRET_DECRYPT_FAILED/)
})

test('reads env-backed secrets without writing files', async () => {
  const dir = await tempDir()
  const store = new SecretStore({ dir, backend: 'env', envPrefix: 'SSH_HOST_' })
  const name = envNameFor(REF, 'SSH_HOST_')
  assert.equal(name, 'SSH_HOST_HOST_ABCD1234_PASSWORD')
  process.env[name] = 'from-env'
  try {
    assert.equal(await store.status(REF), 'available')
    assert.equal(await store.get(REF), 'from-env')
    await assert.rejects(() => store.set(REF, 'x'), /SECRET_ENV_READONLY/)
  } finally {
    delete process.env[name]
  }
  assert.equal(await store.status(REF), 'missing')
})

test('none backend refuses secret access', async () => {
  const store = new SecretStore({ dir: await tempDir(), backend: 'none', envPrefix: 'SSH_HOST_' })
  await assert.rejects(() => store.get(REF), /SECRET_BACKEND_NONE/)
  assert.equal(await store.status(REF), 'unavailable')
})

test('credential files are owner-only on POSIX', async () => {
  if (process.platform === 'win32') return
  const dir = await tempDir()
  const store = new SecretStore({ dir, backend: 'file', envPrefix: 'SSH_HOST_' })
  await store.set(REF, 'secret-value')
  const mode = (await stat(join(dir, 'credentials.json'))).mode & 0o777
  assert.equal(mode, 0o600)
  const keyMode = (await stat(join(dir, 'master.key'))).mode & 0o777
  assert.equal(keyMode, 0o600)
})
