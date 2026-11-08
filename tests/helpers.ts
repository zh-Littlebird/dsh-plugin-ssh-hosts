import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** Unique scratch directory for one test. */
export async function tempDir(prefix = 'dsh-ssh-test-'): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix))
}
