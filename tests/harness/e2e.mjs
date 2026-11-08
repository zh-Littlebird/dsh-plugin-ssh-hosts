// End-to-end harness: registers the real plugin tools against a captured
// registry, then executes them over a real SSH connection and SFTP session.
// Run with:
//   node --import ./tests/harness/register.mjs tests/harness/e2e.mjs
import assert from 'node:assert/strict'
import { readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { apply } from '../../lib/index.js'
import { HostStore } from '../../lib/hosts.js'
import { SecretStore } from '../../lib/secrets.js'

const dataDir = process.env.SSH_HARNESS_DATA_DIR ?? join(process.cwd(), '.ssh-harness-data')
const serverName = 'harness-1'
const port = Number(process.env.SSH_TEST_PORT ?? 22222)
const runId = Date.now().toString(36)
const notePath = `~/notes/hello-${runId}.txt`
const uploadPath = `~/notes/upload-${runId}.txt`

await rm(dataDir, { recursive: true, force: true })
const store = new HostStore(dataDir)
const host = await store.add({
  alias: serverName,
  host: '127.0.0.1',
  port,
  username: 'tester',
  authType: 'password',
  fingerprintPolicy: 'accept-new',
  allowedPaths: ['~'],
  editablePaths: ['~/notes'],
  sudo: { mode: 'nopasswd' },
  services: [
    { name: 'api', directory: '~/notes', description: 'test service', startCommand: 'systemctl restart api', port: 8080 },
  ],
})
const secrets = new SecretStore({ dir: dataDir, backend: 'file', envPrefix: 'SSH_HOST_' })
await secrets.set(host.auth.type === 'password' ? host.auth.secretRef : `host:${host.id}:password`, 'testpass')

const registered = new Map()
const disposers = []
let approvalOutcome = 'rejected'
let approvalCalls = 0
// Mirror the permissions preset the Harness reports to the plugin. The default
// here is the interactive one, so the approval tests below stay meaningful.
let approvalPolicy = 'ask'
const sandboxPolicy = { resolve: () => ({ mode: 'workspace-write' }) }
const approval = {
  async request() {
    approvalCalls++
    return approvalOutcome
  },
  effectivePolicy() {
    return approvalPolicy
  },
}
const ctx = {
  tools: {
    register(definition) {
      registered.set(definition.name, definition)
      return () => registered.delete(definition.name)
    },
  },
  get(name) {
    if (name === 'approval') return approval
    if (name === 'sandboxPolicy') return sandboxPolicy
    return undefined
  },
  effect(fn) {
    const disposer = fn()
    if (typeof disposer === 'function') disposers.push(disposer)
    return () => undefined
  },
}

apply(ctx, {
  dataDir,
  highRiskPolicy: 'ask',
  // The harness has no real session; the per-session consent gate is covered by
  // tests/session-consent.test.ts, so keep the legacy flow here.
  sessionConsent: 'allow',
  timeoutMs: 5000,
  maxTimeoutMs: 10000,
  connectTimeoutMs: 5000,
  maxOutputBytes: 65536,
  audit: true,
})

const expectedTools = [
  'ssh_download',
  'ssh_exec',
  'ssh_host_add',
  'ssh_host_list',
  'ssh_host_remove',
  'ssh_host_update',
  'ssh_read_file',
  'ssh_services',
  'ssh_test',
  'ssh_upload',
  'ssh_write_file',
]
const toolNames = [...registered.keys()].sort()
assert.deepEqual(toolNames, expectedTools, 'tool registration')

const exec = {
  agent: { id: 'agent-harness', session: { id: 'agent-harness', header: { id: 'agent-harness' } } },
  callId: 'call-harness',
  signal: new AbortController().signal,
  deferContext() {},
  concludeTurn() {},
}

const list = await registered.get('ssh_host_list').execute({}, exec)
assert.equal(list.count, 1)
assert.equal(list.hosts[0].alias, serverName)
assert.equal(list.hosts[0].credentialStatus, 'available')
assert.deepEqual(list.hosts[0].editablePaths, ['~/notes'])

const services = await registered.get('ssh_services').execute({ server: serverName }, exec)
assert.equal(services.count, 1)
assert.equal(services.services[0].name, 'api')
assert.equal(services.services[0].directory, '~/notes')

const added = await registered.get('ssh_host_add').execute(
  { alias: 'harness-2', host: '10.0.0.2', username: 'deploy', authType: 'password' },
  exec,
)
assert.equal(added.host.alias, 'harness-2')
assert.equal(added.credentialStatus, 'missing')
assert.equal((await registered.get('ssh_host_list').execute({}, exec)).count, 2)
const removed = await registered.get('ssh_host_remove').execute({ server: 'harness-2' }, exec)
assert.equal(removed.removed, true)
assert.equal((await registered.get('ssh_host_list').execute({}, exec)).count, 1)

const tested = await registered.get('ssh_test').execute({ server: serverName }, exec)
assert.equal(tested.error, null)
assert.equal(tested.authOk, true)
assert.equal(tested.homeDir, '/home/tester')

const uname = await registered.get('ssh_exec').execute({ server: serverName, command: 'uname -a && whoami' }, exec)
assert.equal(uname.exitCode, 0)
assert.match(uname.stdout, /Linux test-host/)
assert.match(uname.stdout, /tester/)
assert.equal(uname.approval, 'not-required')

await assert.rejects(
  () => registered.get('ssh_exec').execute({ server: serverName, command: 'sudo reboot' }, exec),
  (error) => error.code === 'APPROVAL_DENIED',
)
assert.equal(approvalCalls, 1)

approvalOutcome = 'allowed-once'
const approved = await registered.get('ssh_exec').execute({ server: serverName, command: 'sudo reboot' }, exec)
assert.equal(approved.approval, 'granted')
assert.equal(approvalCalls, 2)

// A leading `sudo` is rewritten through the host's configured sudo policy.
const unameRoot = await registered.get('ssh_exec').execute(
  { server: serverName, command: 'sudo id -u' },
  exec,
)
assert.equal(unameRoot.exitCode, 0)
assert.equal(unameRoot.privileged, true)
assert.equal(unameRoot.privilegeMode, 'nopasswd')
assert.match(unameRoot.stdout, /sudo -n/)

// 「完全权限」: prompts are disabled, so risky commands run without asking.
approvalPolicy = 'never'
sandboxPolicy.resolve = () => ({ mode: 'danger-full-access' })
const callsBeforeFullAccess = approvalCalls
const fullAccess = await registered.get('ssh_exec').execute(
  { server: serverName, command: 'systemctl stop nginx' },
  exec,
)
assert.equal(fullAccess.approval, 'full-access')
assert.equal(approvalCalls, callsBeforeFullAccess, 'full access must not ask')
approvalPolicy = 'ask'
sandboxPolicy.resolve = () => ({ mode: 'workspace-write' })

const written = await registered.get('ssh_write_file').execute(
  { server: serverName, path: notePath, content: 'hello from the plugin\n', createDirs: true },
  exec,
)
assert.equal(written.created, true)
const read = await registered.get('ssh_read_file').execute({ server: serverName, path: notePath }, exec)
assert.equal(read.content, 'hello from the plugin\n')
assert.equal(read.truncated, false)

await assert.rejects(
  () => registered.get('ssh_write_file').execute(
    { server: serverName, path: '~/outside.txt', content: 'nope' },
    exec,
  ),
  (error) => error.code === 'EDIT_PATH_DENIED',
)
await assert.rejects(
  () => registered.get('ssh_exec').execute(
    { server: serverName, command: 'echo nope > /tmp/outside.txt', cwd: '~/notes' },
    exec,
  ),
  (error) => error.code === 'EDIT_PATH_DENIED',
)
const editInPlace = await registered.get('ssh_exec').execute(
  { server: serverName, command: 'echo ok > allowed.txt', cwd: '~/notes' },
  exec,
)
assert.equal(editInPlace.exitCode, 0)

const transfers = join(dataDir, 'transfers')
const { mkdir } = await import('node:fs/promises')
await mkdir(transfers, { recursive: true })
await writeFile(join(transfers, 'upload.txt'), 'uploaded content')
const uploaded = await registered.get('ssh_upload').execute(
  { server: serverName, localPath: 'upload.txt', remotePath: uploadPath, createDirs: true },
  exec,
)
assert.equal(uploaded.bytes, 16)
await assert.rejects(
  () => registered.get('ssh_upload').execute(
    { server: serverName, localPath: 'upload.txt', remotePath: '~/outside-upload.txt' },
    exec,
  ),
  (error) => error.code === 'EDIT_PATH_DENIED',
)
const downloaded = await registered.get('ssh_download').execute(
  { server: serverName, remotePath: uploadPath, localPath: 'download.txt' },
  exec,
)
assert.equal(downloaded.bytes, 16)
assert.equal(await readFile(join(transfers, 'download.txt'), 'utf8'), 'uploaded content')

await assert.rejects(
  () => registered.get('ssh_read_file').execute({ server: serverName, path: '/etc/passwd' }, exec),
  (error) => error.code === 'REMOTE_PATH_DENIED',
)

await registered.get('ssh_host_update').execute({ server: serverName, readOnly: true }, exec)
await assert.rejects(
  () => registered.get('ssh_exec').execute({ server: serverName, command: 'uname -a' }, exec),
  (error) => error.code === 'READ_ONLY',
)

const audit = await readFile(join(dataDir, 'audit.log'), 'utf8')
assert.match(audit, /"action":"exec"/)
assert.ok(!audit.includes('testpass'))

for (const dispose of disposers) dispose()
const summary = {
  registeredTools: toolNames,
  hostListCount: list.count,
  services: { count: services.count, first: services.services[0] },
  editablePaths: list.hosts[0].editablePaths,
  sshTest: { authOk: tested.authOk, homeDir: tested.homeDir, hostKeyStatus: tested.hostKeyStatus },
  exec: { exitCode: uname.exitCode, stdout: uname.stdout.trim().split('\n') },
  approval: { rejected: true, granted: approved.approval, calls: approvalCalls },
  files: {
    written: written.path,
    read: read.content.trim(),
    uploaded: uploaded.remotePath,
    downloadedBytes: downloaded.bytes,
  },
  deniedPath: '/etc/passwd',
  readOnly: true,
  auditLines: audit.trim().split('\n').length,
}
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`)
