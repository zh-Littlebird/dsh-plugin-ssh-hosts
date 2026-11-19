import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { atomicWriteFile, windowsAccountName } from '../src/fs-util.js'
import { tempDir } from './helpers.js'

test('atomicWriteFile replaces an existing file and leaves no temp file', async () => {
  const dir = await tempDir('dsh-ssh-atomic-')
  const file = join(dir, 'hosts.json')
  await atomicWriteFile(file, '{"hosts":[]}\n')
  await atomicWriteFile(file, '{"hosts":[1]}\n')
  assert.equal(await readFile(file, 'utf8'), '{"hosts":[1]}\n')
  assert.deepEqual(
    (await readdir(dir)).filter((name) => name.endsWith('.tmp')),
    [],
    'no temp file survives a successful write',
  )
})

test('the Windows account name is domain-qualified and resolvable', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('Windows only')
    return
  }
  const user = await windowsAccountName()
  assert.ok(user !== undefined, 'a Windows account name is always resolved')
  // A bare login name does not resolve on a domain-joined machine, and
  // `icacls` then writes an ACE that cannot be translated to a SID.
  assert.match(user, /^[^\\\s]+\\[^\\\s]+$/, 'the name must be DOMAIN\\user')
  assert.equal(user, await windowsAccountName(), 'the resolved name is cached')
})

test('a written file keeps a usable ACL on Windows', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('Windows only')
    return
  }
  const dir = await tempDir('dsh-ssh-acl-')
  const file = join(dir, 'secrets.json')
  await atomicWriteFile(file, '{}\n')
  // Reading it back proves the ACE written by hardenPermissions matches this
  // process; a name that fails to resolve would deny the owner every right.
  assert.equal(await readFile(file, 'utf8'), '{}\n')
  await atomicWriteFile(file, '{"a":1}\n')
  assert.equal(await readFile(file, 'utf8'), '{"a":1}\n')
})
