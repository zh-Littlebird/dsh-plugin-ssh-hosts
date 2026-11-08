/**
 * Credential storage isolated from the host inventory.
 *
 * `file` encrypts each value with AES-256-GCM under a random 32-byte master
 * key kept beside the store (mode 0600, best-effort Windows ACL). This is
 * deliberately not an OS keychain: it prevents accidental reads, not code
 * running as the same user. `env` reads values from the process environment
 * and writes nothing. `none` refuses all secret access.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { atomicWriteFile, readJson } from './fs-util.js';
import { registerSecret } from './redact.js';
import { SshHostsError } from './types.js';
const CREDENTIALS_FILE = 'credentials.json';
const MASTER_KEY_FILE = 'master.key';
/** Stable environment variable name for one credential reference. */
export function envNameFor(ref, prefix) {
    const suffix = ref
        .replace(/^host:/, '')
        .replace(/:/g, '_')
        .toUpperCase()
        .replace(/[^A-Z0-9_]/g, '_');
    return `${prefix}${suffix}`;
}
export class SecretStore {
    options;
    credentialsFile;
    masterKeyFile;
    queue = Promise.resolve();
    constructor(options) {
        this.options = options;
        this.credentialsFile = join(options.dir, CREDENTIALS_FILE);
        this.masterKeyFile = join(options.dir, MASTER_KEY_FILE);
    }
    /** Whether a usable value is present for this reference. */
    async status(ref) {
        if (this.options.backend === 'none')
            return 'unavailable';
        if (this.options.backend === 'env') {
            return process.env[envNameFor(ref, this.options.envPrefix)] ? 'available' : 'missing';
        }
        const document = await this.readDocument();
        return document.entries[ref] === undefined ? 'missing' : 'available';
    }
    /** Resolve a secret for one connection; the value stays in this process. */
    async get(ref) {
        if (this.options.backend === 'none') {
            throw new SshHostsError('SECRET_BACKEND_NONE', '凭据后端为 none，无法读取密码或私钥口令', '请把 secretsBackend 改为 file 或 env，或由用户在本机配置凭据');
        }
        if (this.options.backend === 'env') {
            const name = envNameFor(ref, this.options.envPrefix);
            const value = process.env[name];
            if (value === undefined || value.length === 0)
                return undefined;
            registerSecret(value);
            return value;
        }
        const document = await this.readDocument();
        const entry = document.entries[ref];
        if (entry === undefined)
            return undefined;
        const key = await this.readMasterKey(false);
        if (key === undefined) {
            throw new SshHostsError('SECRET_KEY_MISSING', '凭据文件存在，但主密钥 master.key 缺失', '请恢复主密钥，或删除 credentials.json 后重新录入凭据');
        }
        const value = this.decrypt(key, ref, entry);
        registerSecret(value);
        return value;
    }
    /** Store or replace one secret. */
    async set(ref, value) {
        if (value.length === 0)
            throw new SshHostsError('SECRET_EMPTY', '凭据不能为空', '请提供非空的密码或口令');
        if (this.options.backend === 'none') {
            throw new SshHostsError('SECRET_BACKEND_NONE', '凭据后端为 none，不能保存凭据', '请改用 file 或 env 后端');
        }
        if (this.options.backend === 'env') {
            throw new SshHostsError('SECRET_ENV_READONLY', 'env 后端不会写入磁盘', `请设置环境变量 ${envNameFor(ref, this.options.envPrefix)}`);
        }
        const run = this.queue.then(async () => {
            const key = await this.readMasterKey(true);
            if (key === undefined)
                throw new SshHostsError('SECRET_KEY_MISSING', '无法创建主密钥', '请检查数据目录权限');
            const document = await this.readDocument();
            document.entries[ref] = this.encrypt(key, ref, value);
            await atomicWriteFile(this.credentialsFile, `${JSON.stringify(document, null, 2)}\n`);
            registerSecret(value);
        });
        this.queue = run.catch(() => undefined);
        await run;
    }
    /** Remove one secret if present. */
    async delete(ref) {
        if (this.options.backend === 'env' || this.options.backend === 'none')
            return false;
        let removed = false;
        const run = this.queue.then(async () => {
            const document = await this.readDocument();
            if (document.entries[ref] === undefined)
                return;
            delete document.entries[ref];
            removed = true;
            await atomicWriteFile(this.credentialsFile, `${JSON.stringify(document, null, 2)}\n`);
        });
        this.queue = run.catch(() => undefined);
        await run;
        return removed;
    }
    /** Remove every credential belonging to one host id. */
    async deleteHost(hostId) {
        if (this.options.backend === 'env' || this.options.backend === 'none')
            return 0;
        let removed = 0;
        const run = this.queue.then(async () => {
            const document = await this.readDocument();
            const prefix = `host:${hostId}:`;
            for (const ref of Object.keys(document.entries)) {
                if (ref.startsWith(prefix)) {
                    delete document.entries[ref];
                    removed++;
                }
            }
            if (removed > 0) {
                await atomicWriteFile(this.credentialsFile, `${JSON.stringify(document, null, 2)}\n`);
            }
        });
        this.queue = run.catch(() => undefined);
        await run;
        return removed;
    }
    async readDocument() {
        const document = await readJson(this.credentialsFile);
        if (document === undefined)
            return { version: 1, entries: {} };
        if (typeof document !== 'object' || document === null || typeof document.entries !== 'object' || document.entries === null) {
            throw new SshHostsError('SECRETS_INVALID', `凭据文件格式无效：${this.credentialsFile}`, '请删除该文件后重新录入凭据');
        }
        return document;
    }
    async readMasterKey(create) {
        let text;
        try {
            text = await readFile(this.masterKeyFile, 'utf8');
        }
        catch (error) {
            if (error.code !== 'ENOENT')
                throw error;
            if (!create)
                return undefined;
            const key = randomBytes(32);
            await atomicWriteFile(this.masterKeyFile, `${key.toString('base64')}\n`);
            return key;
        }
        let key;
        try {
            key = Buffer.from(text.trim(), 'base64');
        }
        catch {
            throw new SshHostsError('SECRET_KEY_INVALID', `主密钥格式无效：${this.masterKeyFile}`, '请恢复主密钥，或删除凭据后重新录入');
        }
        if (key.length !== 32) {
            throw new SshHostsError('SECRET_KEY_INVALID', `主密钥长度无效：${this.masterKeyFile}`, '主密钥必须是 32 字节的 base64 文本');
        }
        return key;
    }
    encrypt(key, ref, value) {
        const iv = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
        cipher.setAAD(Buffer.from(ref, 'utf8'));
        const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
        return {
            iv: iv.toString('base64'),
            tag: cipher.getAuthTag().toString('base64'),
            data: data.toString('base64'),
            updatedAt: new Date().toISOString(),
        };
    }
    decrypt(key, ref, entry) {
        try {
            const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(entry.iv, 'base64'), { authTagLength: 16 });
            decipher.setAAD(Buffer.from(ref, 'utf8'));
            decipher.setAuthTag(Buffer.from(entry.tag, 'base64'));
            return Buffer.concat([decipher.update(Buffer.from(entry.data, 'base64')), decipher.final()]).toString('utf8');
        }
        catch (error) {
            throw new SshHostsError('SECRET_DECRYPT_FAILED', `凭据解密失败：${ref}`, '主密钥与凭据文件不匹配，或凭据文件被篡改；请由用户重新录入该凭据', error);
        }
    }
}
