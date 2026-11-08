import assert from 'node:assert/strict'
import test from 'node:test'
import { forgetSecret, redact, registerSecret } from '../src/redact.js'

test('redacts registered secret values anywhere in the text', () => {
  registerSecret('super-secret-password')
  const text = 'auth failed for super-secret-password and super-secret-password again'
  const output = redact(text)
  assert.ok(!output.includes('super-secret-password'))
  assert.equal(output.split('***REDACTED***').length - 1, 2)
  forgetSecret('super-secret-password')
})

test('redacts a PEM private key block', () => {
  const key = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----'
  const output = redact(`before\n${key}\nafter`)
  assert.ok(!output.includes('AAAA'))
  assert.ok(output.includes('***REDACTED***'))
})

test('redacts password assignments and URL credentials', () => {
  const output = redact('password=hunter2 passphrase: "abc" https://user:pw@example.com/repo')
  assert.ok(!output.includes('hunter2'))
  assert.ok(!output.includes('abc'))
  assert.ok(!output.includes('user:pw'))
})

test('leaves ordinary text untouched', () => {
  assert.equal(redact('uname -a on web-1'), 'uname -a on web-1')
})
