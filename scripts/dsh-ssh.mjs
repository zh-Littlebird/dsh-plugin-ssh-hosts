#!/usr/bin/env node
/**
 * Local credential provisioning for dsh-plugin-ssh-hosts.
 *
 * The model never runs this script and never sees its input. Run it in your own
 * terminal after adding a host:
 *
 *   node scripts/dsh-ssh.mjs set web-1 --password
 *   node scripts/dsh-ssh.mjs set web-1 --passphrase
 *   node scripts/dsh-ssh.mjs set web-1 --sudo          # sudo password mode
 *   SSH_HOST_HOST_AB12CD34_PASSWORD=... node scripts/dsh-ssh.mjs status web-1
 *   node scripts/dsh-ssh.mjs list
 */

import { readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { SecretStore, envNameFor } from '../lib/secrets.js'

function dataDirFrom(option) {
  if (option) return resolve(option)
  const override = process.env.DSH_SSH_HOSTS_DATA_DIR
  if (override && override.trim().length > 0) return resolve(override)
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  return join(home, 'ssh-hosts')
}

async function loadHosts(dataDir) {
  try {
    const text = await readFile(join(dataDir, 'hosts.json'), 'utf8')
    const document = JSON.parse(text)
    return Array.isArray(document) ? document : document.hosts ?? []
  } catch (error) {
    if (error.code === 'ENOENT') return []
    throw error
  }
}

function findHost(hosts, ref) {
  const host = hosts.find((entry) => entry.id === ref || entry.alias === ref)
  if (!host) {
    throw new Error(`未找到主机：${ref}；现有：${hosts.map((entry) => entry.alias).join('、') || '无'}`)
  }
  return host
}

async function promptHidden(question) {
  const stdin = process.stdin
  if (!stdin.isTTY) {
    const chunks = []
    for await (const chunk of stdin) chunks.push(chunk)
    return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '')
  }
  process.stdout.write(question)
  stdin.setRawMode(true)
  stdin.resume()
  stdin.setEncoding('utf8')
  let value = ''
  return new Promise((resolvePromise, reject) => {
    const finish = (error) => {
      stdin.setRawMode(false)
      stdin.pause()
      stdin.removeListener('data', onData)
      if (error) reject(error)
    }
    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === '\r' || char === '\n') {
          process.stdout.write('\n')
          finish()
          resolvePromise(value)
          return
        }
        if (char === '\u0003') {
          process.stdout.write('\n')
          finish(new Error('已取消'))
          return
        }
        if (char === '\u007f' || char === '\b') {
          value = value.slice(0, -1)
          continue
        }
        value += char
      }
    }
    stdin.on('data', onData)
  })
}

async function readSecret(options, kind) {
  if (typeof options.env === 'string') {
    const value = process.env[options.env]
    if (value === undefined || value.length === 0) throw new Error(`环境变量 ${options.env} 为空`)
    return value
  }
  if (options.stdin === true) {
    const chunks = []
    for await (const chunk of process.stdin) chunks.push(chunk)
    return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '')
  }
  return promptHidden(kind === 'passphrase' ? '私钥口令（输入不回显）：' : kind === 'sudo' ? 'sudo 密码（输入不回显）：' : 'SSH 密码（输入不回显）：')
}

async function main() {
  const parsed = parseArgs({
    allowPositionals: true,
    options: {
      'data-dir': { type: 'string' },
      alias: { type: 'string' },
      ref: { type: 'string' },
      password: { type: 'boolean' },
      passphrase: { type: 'boolean' },
      sudo: { type: 'boolean' },
      stdin: { type: 'boolean' },
      env: { type: 'string' },
    },
  })
  const command = parsed.positionals[0] ?? 'list'
  const target = parsed.positionals[1] ?? parsed.values.alias
  const dataDir = dataDirFrom(parsed.values['data-dir'])
  const store = new SecretStore({
    dir: dataDir,
    backend: 'file',
    envPrefix: process.env.SSH_HOST_ENV_PREFIX ?? 'SSH_HOST_',
  })
  const hosts = await loadHosts(dataDir)

  if (command === 'list') {
    if (hosts.length === 0) {
      console.log(`尚未配置主机（${join(dataDir, 'hosts.json')}）。`)
      return
    }
    for (const host of hosts) {
      const ref = host.auth.type === 'password' ? `host:${host.id}:password` : `host:${host.id}:passphrase`
      const status = await store.status(ref)
      const sudo =
        host.sudo === undefined
          ? ''
          : `\tsudo=${host.sudo.mode === 'password' ? await store.status(`host:${host.id}:sudo`) : host.sudo.mode}`
      console.log(`${host.alias}\t${host.username}@${host.host}:${host.port}\t${host.auth.type}\t凭据=${status}${sudo}`)
    }
    return
  }

  if (command === 'status') {
    if (!target) throw new Error('用法：dsh-ssh status <alias> [--password|--passphrase|--sudo]')
    const host = findHost(hosts, target)
    const refs = []
    const wantsSudo = parsed.values.sudo === true
    const wantsPassword = parsed.values.password === true || (!wantsSudo && host.auth.type === 'password' && parsed.values.passphrase !== true)
    const wantsPassphrase = parsed.values.passphrase === true || (!wantsSudo && host.auth.type === 'key' && parsed.values.password !== true)
    if (wantsPassword) refs.push({ kind: 'password', ref: `host:${host.id}:password` })
    if (wantsPassphrase) refs.push({ kind: 'passphrase', ref: `host:${host.id}:passphrase` })
    if (wantsSudo) {
      if (host.sudo === undefined) throw new Error(`${host.alias} 尚未配置 sudo；请先在 hosts.json 或 Web 页面启用`)
      refs.push({ kind: 'sudo', ref: `host:${host.id}:sudo` })
    }
    for (const { kind, ref } of refs) {
      console.log(`${host.alias} ${kind}: ${await store.status(ref)} (${ref})`)
    }
    return
  }

  if (command === 'set') {
    if (!target && typeof parsed.values.ref !== 'string') throw new Error('用法：dsh-ssh set <alias> --password|--passphrase|--sudo')
    const host = target ? findHost(hosts, target) : undefined
    const ref = typeof parsed.values.ref === 'string' ? parsed.values.ref : undefined
    const kind = parsed.values.sudo === true ? 'sudo' : parsed.values.passphrase === true ? 'passphrase' : 'password'
    if (kind === 'sudo' && host !== undefined && host.sudo === undefined) {
      throw new Error(`${host.alias} 尚未配置 sudo；请先在 hosts.json 或 Web 页面启用密码模式`)
    }
    const effectiveRef = ref ?? (host ? `host:${host.id}:${kind}` : undefined)
    if (!effectiveRef) throw new Error('缺少 --ref 或主机别名')
    const value = await readSecret(parsed.values, kind)
    if (!value) throw new Error('凭据为空')
    await store.set(effectiveRef, value)
    console.log(`已加密保存 ${kind}：${effectiveRef}（文件权限已收紧；不写入 hosts.json）`)
    if (host && kind === 'password' && host.auth.type === 'key') {
      console.log(`提示：${host.alias} 当前使用私钥认证。若要改用密码，请运行 ssh_host_update 把 authType 改为 password。`)
    }
    return
  }

  if (command === 'delete') {
    if (!target) throw new Error('用法：dsh-ssh delete <alias> [--password|--passphrase|--sudo]')
    const host = findHost(hosts, target)
    const kinds = []
    if (parsed.values.sudo === true) kinds.push('sudo')
    else {
      if (parsed.values.password === true || parsed.values.passphrase !== true) kinds.push('password')
      if (parsed.values.passphrase === true) kinds.push('passphrase')
    }
    for (const kind of kinds) {
      const removed = await store.delete(`host:${host.id}:${kind}`)
      console.log(`${host.alias} ${kind}: ${removed ? '已删除' : '不存在'}`)
    }
    return
  }

  console.log('命令：list | status <alias> | set <alias> --password|--passphrase|--sudo | delete <alias>')
  console.log(`数据目录：${dataDir}`)
  console.log(`env 后端示例：${envNameFor('host:host_abcd1234:password', 'SSH_HOST_')}=...`)
}

main().catch((error) => {
  console.error(`错误：${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
