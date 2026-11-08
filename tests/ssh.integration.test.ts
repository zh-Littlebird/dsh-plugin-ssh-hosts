import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import { after, before, test } from 'node:test'
import ssh2 from 'ssh2'
import type { Connection, Server as SshServer, ServerChannel } from 'ssh2'
import { withDefaults } from '../src/config.js'
import { SshManager } from '../src/ssh.js'
import type { HostRecord } from '../src/types.js'
import { SshHostsError } from '../src/types.js'
import { tempDir } from './helpers.js'

const { Server, utils } = ssh2

const PASSWORD = 'correct horse battery staple'
const USER = 'deploy'
const HOME = '/home/deploy'

let server: SshServer
let port = 0
let connections = 0
let manager: SshManager
let learned: string[] = []
let dataDir = ''
const liveClients = new Set<Connection>()

function makeHost(overrides: Partial<HostRecord> = {}): HostRecord {
  const now = new Date().toISOString()
  return {
    id: 'host_11111111',
    alias: 'test-1',
    host: '127.0.0.1',
    port,
    username: USER,
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

function generateEd25519(): { private: string; public: string } {
  return utils.generateKeyPairSync('ed25519') as unknown as { private: string; public: string }
}

function handleCommand(command: string, stream: ServerChannel): void {
  if (command.includes('printf %s "$HOME"')) {
    stream.exit(0)
    stream.end(HOME)
    return
  }
  // Privileged commands are wrapped as `sudo -n|-S ... -- sh -c '...'`.
  if (command.includes('sudo -S')) {
    let input = ''
    stream.on('data', (chunk: Buffer) => {
      input += chunk.toString('utf8')
    })
    stream.on('end', () => {
      stream.exit(0)
      stream.end(`sudo-stdin:${input.replace(/\r?\n$/u, '')}\n`)
    })
    stream.on('error', () => undefined)
    return
  }
  if (command.includes('sudo -n')) {
    stream.exit(0)
    stream.end('root\n')
    return
  }
  if (command.includes('sleep 30')) return
  if (command.includes('big-output')) {
    stream.exit(0)
    stream.end(Buffer.from('x'.repeat(1_000_000)))
    return
  }
  if (command.includes('echo hello')) {
    stream.exit(0)
    stream.end('hello\n')
    return
  }
  if (command.includes('exit 3')) {
    stream.exit(3)
    stream.end('')
    return
  }
  if (command.includes('write stderr')) {
    stream.exit(1)
    stream.stderr.write('something went wrong\n')
    stream.end('partial stdout\n')
    return
  }
  stream.exit(127)
  stream.stderr.write(`sh: ${command}: not found\n`)
  stream.end('')
}

before(async () => {
  dataDir = await tempDir()
  const hostKey = generateEd25519().private
  server = new Server({ hostKeys: [hostKey] }, (client) => {
    liveClients.add(client)
    client.on('close', () => liveClients.delete(client))
    client.on('error', () => undefined)
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.password === PASSWORD) {
        ctx.accept()
        return
      }
      if (ctx.method === 'publickey' && ctx.key.algo === 'ssh-ed25519') {
        ctx.accept()
        return
      }
      ctx.reject(['password', 'publickey'])
    })
    client.on('ready', () => {
      connections++
      client.on('session', (accept) => {
        const session = accept()
        session.on('sftp', (_accept: unknown, reject: () => void) => reject())
        session.on('exec', (acceptExec, _rejectExec, info) => {
          const stream = acceptExec()
          handleCommand(info.command, stream)
        })
      })
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  port = (server.address() as AddressInfo).port
  const config = withDefaults({
    dataDir,
    connectTimeoutMs: 3_000,
    timeoutMs: 3_000,
    maxTimeoutMs: 5_000,
    idleTimeoutMs: 1_000,
    maxConcurrentPerHost: 2,
    maxOutputBytes: 10_000,
  })
  manager = new SshManager({
    config,
    credentials: async (host) => {
      if (host.username === 'bad') return { password: 'wrong-password' }
      if (host.username === 'keyed') {
        return { privateKey: Buffer.from(generateEd25519().private, 'utf8') }
      }
      return { password: PASSWORD }
    },
    onFingerprint: async (host, fingerprint) => {
      learned.push(fingerprint)
    },
    debug: () => undefined,
  })
})

after(async () => {
  await manager.dispose()
  for (const client of liveClients) client.end()
  await new Promise<void>((resolve) => setTimeout(resolve, 100))
  await Promise.race([
    new Promise<void>((resolve) => server.close(() => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, 2_000)),
  ])
})

test('strict policy refuses an unknown host key but reports its fingerprint', async () => {
  const result = await manager.test(makeHost())
  assert.equal(result.error?.code, 'HOST_KEY_UNKNOWN')
  assert.match(result.hostKeyFingerprint ?? '', /^SHA256:/)
  assert.equal(learned.length, 0)
})

test('accept-new learns the host key and reports the home directory', async () => {
  const result = await manager.test(makeHost({ fingerprintPolicy: 'accept-new' }))
  assert.equal(result.error, null)
  assert.equal(result.hostKeyStatus, 'learned')
  assert.equal(result.homeDir, HOME)
  assert.equal(learned.length, 1)
})

test('exec returns stdout, exit code, and cwd', async () => {
  const host = makeHost({ fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() } })
  const result = await manager.exec(host, 'echo hello')
  assert.equal(result.exitCode, 0)
  assert.equal(result.stdout, 'hello\n')
  assert.equal(result.stderr, '')
  assert.equal(result.cwd, HOME)
  assert.equal(result.timedOut, false)
  assert.equal(result.truncated, false)
})

test('a non-zero exit is a result, not an exception', async () => {
  const host = makeHost({ fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() } })
  const result = await manager.exec(host, 'exit 3')
  assert.equal(result.exitCode, 3)
})

test('stderr is captured separately', async () => {
  const host = makeHost({ fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() } })
  const result = await manager.exec(host, 'write stderr')
  assert.equal(result.exitCode, 1)
  assert.equal(result.stdout, 'partial stdout\n')
  assert.equal(result.stderr, 'something went wrong\n')
})

test('timeout interrupts the channel and keeps partial state', async () => {
  const host = makeHost({ fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() } })
  const started = Date.now()
  const result = await manager.exec(host, 'sleep 30', { timeoutMs: 500 })
  assert.equal(result.timedOut, true)
  assert.ok(Date.now() - started < 4_000)
})

test('large output is truncated with head and tail and an exact original size', async () => {
  const host = makeHost({ fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() } })
  const result = await manager.exec(host, 'big-output', { maxOutputBytes: 10_000 })
  assert.equal(result.truncated, true)
  assert.ok(result.originalBytes >= 1_000_000)
  assert.match(result.stdout, /truncated \d+ bytes/)
})

test('reuses one pooled connection for consecutive commands', async () => {
  const host = makeHost({
    id: 'host_22222222',
    fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() },
  })
  const beforeCount = connections
  await manager.exec(host, 'echo hello')
  await manager.exec(host, 'echo hello')
  assert.equal(connections, beforeCount + 1)
})

test('wrong password reports authentication failure without throwing secrets', async () => {
  const result = await manager.test(makeHost({ username: 'bad', fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() } }))
  assert.equal(result.error?.code, 'AUTH_FAILED')
  assert.equal(result.authOk, false)
  assert.ok(!JSON.stringify(result).includes('wrong-password'))
})

test('private-key authentication works', async () => {
  const host = makeHost({
    username: 'keyed',
    auth: { type: 'key', privateKeyPath: '/dev/null' },
    fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() },
  })
  const result = await manager.exec(host, 'echo hello')
  assert.equal(result.exitCode, 0)
})

test('a changed host key is refused with both fingerprints', async () => {
  const result = await manager.test(makeHost({ fingerprint: { sha256: 'SHA256:oldfingerprint', addedAt: new Date().toISOString() } }))
  assert.equal(result.error?.code, 'HOST_KEY_MISMATCH')
  assert.equal(result.hostKeyStatus, 'changed')
  assert.match(result.error?.hint ?? '', /SHA256:oldfingerprint/)
})

test('an aborted call rejects with ABORTED', async () => {
  const host = makeHost({ fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() } })
  const controller = new AbortController()
  const promise = manager.exec(host, 'sleep 30', { signal: controller.signal, timeoutMs: 5_000 })
  setTimeout(() => controller.abort(), 100)
  await assert.rejects(promise, (error: unknown) => error instanceof SshHostsError && error.code === 'ABORTED')
})

test('privileged nopasswd commands run through sudo and report the mode', async () => {
  const host = makeHost({
    id: 'host_33333333',
    fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() },
  })
  const result = await manager.exec(host, 'whoami', { privilege: { mode: 'nopasswd' } })
  assert.equal(result.exitCode, 0)
  assert.equal(result.stdout, 'root\n')
  assert.equal(result.privileged, true)
  assert.equal(result.privilegeMode, 'nopasswd')
})

test('password-mode sudo receives the password over stdin', async () => {
  const host = makeHost({
    id: 'host_44444444',
    fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() },
  })
  const result = await manager.exec(host, 'whoami', {
    privilege: { mode: 'password', password: 'sudo-secret-value' },
  })
  assert.equal(result.exitCode, 0)
  assert.equal(result.stdout, 'sudo-stdin:sudo-secret-value\n')
  assert.equal(result.privilegeMode, 'password')
})

test('privileged commands skip the editablePaths edit guard but keep deniedPaths', async () => {
  const host = makeHost({
    id: 'host_55555555',
    fingerprint: { sha256: learned[0] as string, addedAt: new Date().toISOString() },
    editablePaths: [],
  })
  await assert.rejects(
    () => manager.exec(host, 'touch /tmp/outside.txt'),
    (error: unknown) => error instanceof SshHostsError && error.code === 'EDIT_PATH_DENIED',
  )
  const privileged = await manager.exec(host, 'touch /tmp/outside.txt', { privilege: { mode: 'nopasswd' } })
  assert.equal(privileged.privileged, true)

  await assert.rejects(
    () => manager.exec(host, 'cat ~/.ssh/id_rsa', { privilege: { mode: 'nopasswd' } }),
    (error: unknown) => error instanceof SshHostsError && error.code === 'COMMAND_PATH_DENIED',
  )
})
