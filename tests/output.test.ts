import assert from 'node:assert/strict'
import test from 'node:test'
import { BoundedOutput, formatBytes } from '../src/output.js'

test('keeps a stream below the limit unchanged', () => {
  const output = new BoundedOutput(1_000)
  output.push(Buffer.from('hello '))
  output.push(Buffer.from('world'))
  const captured = output.capture()
  assert.equal(captured.text, 'hello world')
  assert.equal(captured.truncated, false)
  assert.equal(captured.originalBytes, 11)
})

test('keeps head and tail with an explicit loss marker', () => {
  const output = new BoundedOutput(1_000)
  for (let index = 0; index < 100; index++) output.push(Buffer.from('a'.repeat(100)))
  const captured = output.capture()
  assert.equal(captured.truncated, true)
  assert.equal(captured.originalBytes, 10_000)
  assert.match(captured.text, /truncated 9000 bytes/)
  assert.ok(captured.text.startsWith('a'.repeat(500)))
  assert.ok(captured.text.endsWith('a'.repeat(500)))
  assert.ok(captured.bytes <= 1_100)
})

test('counts bytes even when nothing is retained yet', () => {
  const output = new BoundedOutput(20)
  output.push(Buffer.from('0123456789abcdefghij'))
  output.push(Buffer.from('0123456789abcdefghij'))
  const captured = output.capture()
  assert.equal(captured.originalBytes, 40)
  assert.equal(captured.truncated, true)
  assert.ok(captured.text.includes('truncated 20 bytes'))
})

test('formats human byte counts', () => {
  assert.equal(formatBytes(12), '12 B')
  assert.equal(formatBytes(2_048), '2.0 KiB')
  assert.equal(formatBytes(2 * 1024 * 1024), '2.00 MiB')
})
