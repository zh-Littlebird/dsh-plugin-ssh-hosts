/** Small filesystem helpers shared by the stores and the transfer tools. */

import { chmod, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { userInfo } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { SshHostsError } from './types.js'

const execFileAsync = promisify(execFile)

/** Create a directory (recursively) with a best-effort private mode. */
export async function ensureDir(dir: string, mode = 0o700): Promise<void> {
  await mkdir(dir, { recursive: true, mode })
  await hardenPermissions(dir, mode)
}

/** Tighten a path to owner-only access. Windows uses a best-effort ACL. */
export async function hardenPermissions(target: string, mode: number): Promise<void> {
  try {
    await chmod(target, mode)
  } catch {
    // The filesystem may not support POSIX modes; the ACL step below still runs.
  }
  if (process.platform !== 'win32') return
  try {
    const user = userInfo().username
    // A directory needs inheritable entries, otherwise children created by
    // another process (a hand-edited hosts.json, an editor's atomic rename)
    // would inherit no allow ACE at all and become unreadable.
    const info = await stat(target).catch(() => undefined)
    const grant = info?.isDirectory() === true ? `${user}:(OI)(CI)F` : `${user}:F`
    await execFileAsync('icacls', [target, '/inheritance:r', '/grant:r', grant], {
      timeout: 3_000,
      windowsHide: true,
    })
  } catch {
    // ACL tightening is defense in depth; never fail an operation over it.
  }
}

/**
 * Write a file through a uniquely named sibling and rename it into place, so a
 * crash cannot leave a half-written configuration or credential store.
 */
export async function atomicWriteFile(file: string, data: string | Uint8Array, mode = 0o600): Promise<void> {
  await ensureDir(dirname(file))
  const temp = join(dirname(file), `.${basename(file)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`)
  try {
    await writeFile(temp, data, { mode })
    await hardenPermissions(temp, mode)
    await rename(temp, file)
    await hardenPermissions(file, mode)
  } catch (error) {
    await rm(temp, { force: true }).catch(() => undefined)
    throw error
  }
}

/** Parse a JSON file, reporting path and position for malformed input. */
export async function readJson<T>(file: string): Promise<T | undefined> {
  let text: string
  try {
    text = await readFile(file, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  try {
    return JSON.parse(text) as T
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new SshHostsError('STORAGE_INVALID', `配置文件不是合法 JSON：${file}`, `请修复该文件后重试（${message}）`)
  }
}

/** Whether a local path exists. */
export async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path)
    return true
  } catch {
    return false
  }
}

/** Resolve a user-supplied local path against a root and require containment. */
export function resolveInside(root: string, candidate: string): string {
  const resolvedRoot = resolve(root)
  const resolved = resolve(resolvedRoot, candidate)
  const prefix = resolvedRoot.endsWith('\\') || resolvedRoot.endsWith('/') ? resolvedRoot : `${resolvedRoot}${process.platform === 'win32' ? '\\' : '/'}`
  if (resolved !== resolvedRoot && !resolved.startsWith(prefix)) {
    throw new SshHostsError('LOCAL_PATH_DENIED', `本地路径越界：${candidate}`, `只允许访问 ${resolvedRoot} 及其子目录`)
  }
  return resolved
}

/** Whether `child` is the same path as, or below, `parent`. */
export function isPathInside(parent: string, child: string): boolean {
  const normalizedParent = resolve(parent)
  const normalizedChild = resolve(child)
  if (normalizedParent === normalizedChild) return true
  const prefix = normalizedParent.endsWith('\\') || normalizedParent.endsWith('/') ? normalizedParent : `${normalizedParent}${process.platform === 'win32' ? '\\' : '/'}`
  return normalizedChild.startsWith(prefix)
}
