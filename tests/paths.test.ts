import assert from 'node:assert/strict'
import test from 'node:test'
import {
  assertCommandPathsAllowed,
  assertRemoteEditable,
  assertRemotePathAllowed,
  expandRemotePath,
  extractPathTokens,
  resolveRemoteCwd,
  shellQuote,
  wrapCommand,
  type RemotePathPolicy,
} from '../src/paths.js'
import { assertCommandEditsAllowed, detectCommandEdit } from '../src/edits.js'

const policy: RemotePathPolicy = {
  home: '/home/deploy',
  cwd: '/home/deploy/app',
  allowedPaths: ['~', '/tmp'],
  editablePaths: ['~/app'],
  deniedPaths: ['~/.ssh', '/etc/shadow'],
}

test('expands tilde, absolute, and relative paths', () => {
  assert.equal(expandRemotePath('~', policy.cwd, policy.home), '/home/deploy')
  assert.equal(expandRemotePath('~/app', policy.cwd, policy.home), '/home/deploy/app')
  assert.equal(expandRemotePath('/var/log', policy.cwd, policy.home), '/var/log')
  assert.equal(expandRemotePath('../../etc', policy.cwd, policy.home), '/home/etc')
  assert.equal(expandRemotePath('.', policy.cwd, policy.home), '/home/deploy/app')
})

test('refuses paths outside allowed roots and inside denied roots', () => {
  assert.equal(assertRemotePathAllowed('/home/deploy/app/x', policy), '/home/deploy/app/x')
  assert.equal(assertRemotePathAllowed('/tmp/work', policy), '/tmp/work')
  assert.throws(() => assertRemotePathAllowed('/etc/passwd', policy), /REMOTE_PATH_DENIED|越界/)
  assert.throws(() => assertRemotePathAllowed('/home/deploy/.ssh/id_rsa', policy), /禁止访问/)
  assert.throws(() => assertRemotePathAllowed('/etc/shadow', policy), /禁止访问/)
})

test('resolves the default cwd and rejects an out-of-policy one', () => {
  const base = { home: policy.home, allowedPaths: policy.allowedPaths, editablePaths: policy.editablePaths, deniedPaths: policy.deniedPaths }
  assert.equal(resolveRemoteCwd(undefined, base), '/home/deploy')
  assert.equal(resolveRemoteCwd('~/app', base), '/home/deploy/app')
  assert.throws(() => resolveRemoteCwd('/etc', base), /越界/)
})

test('confines writes to editablePaths', () => {
  assert.equal(assertRemoteEditable('/home/deploy/app/x', policy), '/home/deploy/app/x')
  assert.throws(() => assertRemoteEditable('/tmp/x', policy), /EDIT_PATH_DENIED|可编辑目录/)
  assert.throws(() => assertRemoteEditable('/home/deploy/other/x', policy), /EDIT_PATH_DENIED|可编辑目录/)
  assert.throws(
    () => assertRemoteEditable('/home/deploy/app/x', { ...policy, editablePaths: [] }),
    /EDIT_PATH_DENIED|未配置 editablePaths/,
  )
})

test('detects edit-like commands', () => {
  assert.equal(detectCommandEdit('echo hi > ~/app/x').edits, true)
  assert.equal(detectCommandEdit('sed -i s/a/b/ file').edits, true)
  assert.equal(detectCommandEdit('cp a b').edits, true)
  assert.equal(detectCommandEdit('rm -f x').edits, true)
  assert.equal(detectCommandEdit('ls -la').edits, false)
  assert.equal(detectCommandEdit('grep x file 2>/dev/null').edits, false)
})

test('guards edit-like commands with cwd and path checks', () => {
  assert.doesNotThrow(() => assertCommandEditsAllowed('echo hi > out.txt', policy))
  assert.throws(() => assertCommandEditsAllowed('echo hi > /tmp/out.txt', policy), /EDIT_PATH_DENIED|可编辑目录/)
  assert.throws(
    () => assertCommandEditsAllowed('echo hi > out.txt', { ...policy, cwd: '/home/deploy' }),
    /EDIT_PATH_DENIED|editablePaths/,
  )
  assert.doesNotThrow(() => assertCommandEditsAllowed('ls -la /tmp', policy))
  assert.throws(
    () => assertCommandEditsAllowed('touch out.txt', { ...policy, editablePaths: [] }),
    /EDIT_PATH_DENIED|未配置 editablePaths/,
  )
})

test('extracts path-like tokens through quotes and redirections', () => {
  const tokens = extractPathTokens('cat /etc/passwd > /tmp/out 2>/dev/null "a b" --file=/var/log/x')
  assert.ok(tokens.includes('/etc/passwd'))
  assert.ok(tokens.includes('/tmp/out'))
  assert.ok(tokens.includes('/dev/null'))
  assert.ok(tokens.includes('/var/log/x'))
})

test('denies command arguments in denied paths even without strict mode', () => {
  assert.throws(() => assertCommandPathsAllowed('cat /home/deploy/.ssh/id_rsa', policy, false), /COMMAND_PATH_DENIED|禁止的路径/)
  assert.throws(() => assertCommandPathsAllowed('cat ../.ssh/id_rsa', policy, false), /COMMAND_PATH_DENIED|禁止的路径/)
  assert.doesNotThrow(() => assertCommandPathsAllowed('ls -la /var/log', policy, false))
})

test('strict mode confines absolute command paths to the allowlist', () => {
  assert.throws(() => assertCommandPathsAllowed('ls /var/log', policy, true), /越界路径/)
  assert.doesNotThrow(() => assertCommandPathsAllowed('ls /tmp', policy, true))
})

test('quotes shell arguments and wraps cwd', () => {
  assert.equal(shellQuote("/home/o'brien"), `'/home/o'\\''brien'`)
  assert.equal(wrapCommand('pwd', '/tmp'), `cd -- '/tmp' && pwd`)
})
