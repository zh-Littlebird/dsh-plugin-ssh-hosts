// Seed one host plus its password into a scratch data directory for manual E2E runs.
// Usage: node tests/fixtures/seed-host.mjs <dataDir> [alias] [port]
import { join } from 'node:path'
import { HostStore } from '../../lib/hosts.js'
import { SecretStore } from '../../lib/secrets.js'

const dataDir = process.argv[2]
const alias = process.argv[3] ?? 'dev-1'
const port = Number(process.argv[4] ?? 22222)
if (!dataDir) {
  console.error('usage: node tests/fixtures/seed-host.mjs <dataDir> [alias] [port]')
  process.exit(1)
}

const store = new HostStore(dataDir)
let host
try {
  host = await store.add({
    alias,
    host: '127.0.0.1',
    port,
    username: 'tester',
    authType: 'password',
    fingerprintPolicy: 'accept-new',
    allowedPaths: ['~'],
    editablePaths: ['~/notes'],
    services: [
      { name: 'demo', directory: '~/notes', description: 'local test service', startCommand: 'echo start', port: 8080 },
    ],
  })
} catch (error) {
  if (!String(error).includes('HOST_ALIAS_EXISTS')) throw error
  host = await store.find(alias)
}

const secrets = new SecretStore({ dir: dataDir, backend: 'file', envPrefix: 'SSH_HOST_' })
await secrets.set(host.auth.type === 'password' ? host.auth.secretRef : `host:${host.id}:password`, 'testpass')
console.log(JSON.stringify({ id: host.id, alias: host.alias, host: host.host, port: host.port, dataDir: join(dataDir, 'hosts.json') }, null, 2))
