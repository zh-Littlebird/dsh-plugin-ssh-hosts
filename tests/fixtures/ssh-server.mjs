// Local test SSH server for end-to-end verification of the plugin.
// Not part of the published package: it serves an in-memory POSIX filesystem.
import ssh2 from 'ssh2'
import { posix } from 'node:path'
import { randomBytes } from 'node:crypto'

const { Server, utils } = ssh2
const port = Number(process.env.SSH_TEST_PORT ?? 22222)
const password = process.env.SSH_TEST_PASSWORD ?? 'testpass'
const HOME = '/home/tester'
const hostKey = utils.generateKeyPairSync('ed25519').private

const dirs = new Set(['/', '/home', HOME, '/tmp'])
const files = new Map()
const handles = new Map()

function normalize(input) {
  if (input === '~') return HOME
  if (input.startsWith('~/')) return posix.normalize(posix.join(HOME, input.slice(2)))
  if (input.startsWith('/')) return posix.normalize(input)
  return posix.normalize(posix.join(HOME, input))
}

function attrsFor(path, size = 0) {
  return dirs.has(path)
    ? { mode: 0o040755, uid: 1000, gid: 1000, size: 0, atime: 0, mtime: 0 }
    : { mode: 0o100644, uid: 1000, gid: 1000, size, atime: 0, mtime: 0 }
}

const STATUS = { OK: 0, EOF: 1, NO_SUCH_FILE: 2, PERMISSION_DENIED: 3, FAILURE: 4 }

function sftpHandlers(sftp) {
  sftp.on('REALPATH', (reqId, path) => {
    const resolved = normalize(path)
    sftp.name(reqId, [{ filename: resolved, longname: resolved, attrs: attrsFor(resolved) }])
  })
  sftp.on('STAT', (reqId, path) => {
    const resolved = normalize(path)
    if (!dirs.has(resolved) && !files.has(resolved)) {
      sftp.status(reqId, STATUS.NO_SUCH_FILE)
      return
    }
    sftp.attrs(reqId, attrsFor(resolved, files.get(resolved)?.length ?? 0))
  })
  sftp.on('LSTAT', (reqId, path) => {
    const resolved = normalize(path)
    if (!dirs.has(resolved) && !files.has(resolved)) {
      sftp.status(reqId, STATUS.NO_SUCH_FILE)
      return
    }
    sftp.attrs(reqId, attrsFor(resolved, files.get(resolved)?.length ?? 0))
  })
  sftp.on('OPEN', (reqId, filename, flags) => {
    const resolved = normalize(filename)
    const readable = (flags & 0x1) !== 0
    const writable = (flags & 0x2) !== 0
    const create = (flags & 0x8) !== 0
    const truncate = (flags & 0x10) !== 0
    if (dirs.has(resolved)) {
      sftp.status(reqId, STATUS.FAILURE)
      return
    }
    if (readable && !writable && !files.has(resolved)) {
      sftp.status(reqId, STATUS.NO_SUCH_FILE)
      return
    }
    if (writable && create && !files.has(resolved)) files.set(resolved, Buffer.alloc(0))
    if (writable && truncate) files.set(resolved, Buffer.alloc(0))
    if (!files.has(resolved)) {
      sftp.status(reqId, STATUS.NO_SUCH_FILE)
      return
    }
    const handle = randomBytes(4)
    handles.set(handle.toString('hex'), { path: resolved })
    sftp.handle(reqId, handle)
  })
  sftp.on('READ', (reqId, handle, offset, length) => {
    const entry = handles.get(handle.toString('hex'))
    if (!entry) {
      sftp.status(reqId, STATUS.FAILURE)
      return
    }
    const data = files.get(entry.path) ?? Buffer.alloc(0)
    if (offset >= data.length) {
      sftp.status(reqId, STATUS.EOF)
      return
    }
    sftp.data(reqId, data.subarray(offset, Math.min(data.length, offset + length)))
  })
  sftp.on('WRITE', (reqId, handle, offset, data) => {
    const entry = handles.get(handle.toString('hex'))
    if (!entry) {
      sftp.status(reqId, STATUS.FAILURE)
      return
    }
    const current = files.get(entry.path) ?? Buffer.alloc(0)
    const next = Buffer.alloc(Math.max(current.length, offset + data.length))
    current.copy(next, 0)
    data.copy(next, offset)
    files.set(entry.path, next)
    sftp.status(reqId, STATUS.OK)
  })
  sftp.on('FSTAT', (reqId, handle) => {
    const entry = handles.get(handle.toString('hex'))
    if (!entry) {
      sftp.status(reqId, STATUS.FAILURE)
      return
    }
    sftp.attrs(reqId, attrsFor(entry.path, files.get(entry.path)?.length ?? 0))
  })
  sftp.on('CLOSE', (reqId, handle) => {
    handles.delete(handle.toString('hex'))
    sftp.status(reqId, STATUS.OK)
  })
  sftp.on('MKDIR', (reqId, path) => {
    const resolved = normalize(path)
    if (dirs.has(resolved)) {
      sftp.status(reqId, STATUS.FAILURE)
      return
    }
    dirs.add(resolved)
    sftp.status(reqId, STATUS.OK)
  })
  sftp.on('REMOVE', (reqId, path) => {
    files.delete(normalize(path))
    sftp.status(reqId, STATUS.OK)
  })
  sftp.on('RENAME', (reqId, oldPath, newPath) => {
    const from = normalize(oldPath)
    const to = normalize(newPath)
    const data = files.get(from)
    if (data === undefined) {
      sftp.status(reqId, STATUS.NO_SUCH_FILE)
      return
    }
    files.delete(from)
    files.set(to, data)
    sftp.status(reqId, STATUS.OK)
  })
  sftp.on('SETSTAT', (reqId) => sftp.status(reqId, STATUS.OK))
}

const server = new Server({ hostKeys: [hostKey] }, (client) => {
  client.on('error', () => undefined)
  client.on('authentication', (ctx) => {
    if (ctx.method === 'password' && ctx.password === password) {
      ctx.accept()
      return
    }
    ctx.reject(['password'])
  })
  client.on('ready', () => {
    client.on('session', (accept) => {
      const session = accept()
      session.on('sftp', (acceptSftp) => sftpHandlers(acceptSftp()))
      session.on('exec', (acceptExec, _rejectExec, info) => {
        const stream = acceptExec()
        const command = info.command
        if (command.includes('printf %s "$HOME"')) {
          stream.exit(0)
          stream.end(HOME)
          return
        }
        if (command.includes('uname') && command.includes('whoami')) {
          stream.exit(0)
          stream.end('Linux test-host 6.1.0-test #1 SMP x86_64 GNU/Linux\ntester\n')
          return
        }
        if (command.includes('uname')) {
          stream.exit(0)
          stream.end('Linux test-host 6.1.0-test #1 SMP x86_64 GNU/Linux\n')
          return
        }
        if (command.includes('whoami')) {
          stream.exit(0)
          stream.end('tester\n')
          return
        }
        if (command.includes('exit 3')) {
          stream.exit(3)
          stream.end('failed intentionally\n')
          return
        }
        stream.exit(0)
        stream.end(`ran: ${command}\n`)
      })
    })
  })
})

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`ssh-test-server listening on 127.0.0.1:${port}\n`)
})

process.on('SIGTERM', () => server.close(() => process.exit(0)))
process.on('SIGINT', () => server.close(() => process.exit(0)))
