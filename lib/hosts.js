/** Durable host inventory: validation, atomic persistence, and redacted views. */
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { atomicWriteFile, readJson } from './fs-util.js';
import { SshHostsError } from './types.js';
import { SUDO_USER_PATTERN, sudoPasswordRef } from './sudo.js';
export const HOSTS_FILE = 'hosts.json';
export const DEFAULT_DENIED_PATHS = ['~/.ssh', '/etc/shadow', '/etc/sudoers', '/etc/sudoers.d'];
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function requireString(value, field, index) {
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条缺少有效字段 ${field}`, '请检查该主机的配置');
    }
    return value.trim();
}
function optionalString(value) {
    return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}
function stringArray(value, fallback, field, index) {
    if (value === undefined || value === null)
        return [...fallback];
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string' || entry.trim().length === 0)) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条的 ${field} 必须是非空字符串数组`, '请检查该主机的配置');
    }
    return value.map((entry) => entry.trim());
}
/** Validate the service directory notes attached to one host. */
export function validateServices(value, index) {
    if (value === undefined || value === null)
        return [];
    const prefix = index === null ? '服务配置' : `hosts.json 第 ${index + 1} 条`;
    if (!Array.isArray(value)) {
        throw new SshHostsError('STORAGE_INVALID', `${prefix}的 services 必须是数组`, '每项包含 name、directory 和可选说明');
    }
    const names = new Set();
    return value.map((entry, position) => {
        if (!isRecord(entry)) {
            throw new SshHostsError('STORAGE_INVALID', `${prefix} services[${position}] 不是对象`, '每项包含 name、directory 和可选说明');
        }
        const name = typeof entry.name === 'string' ? entry.name.trim() : '';
        if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) {
            throw new SshHostsError('INVALID_SERVICE', `${prefix} services[${position}] 的 name 无效`, '服务名只能包含字母、数字、点、下划线和连字符');
        }
        if (names.has(name)) {
            throw new SshHostsError('INVALID_SERVICE', `${prefix} 存在重复服务名：${name}`, '每台服务器的服务名必须唯一');
        }
        names.add(name);
        const directory = typeof entry.directory === 'string' ? entry.directory.trim() : '';
        if (directory.length === 0 || !(directory.startsWith('/') || directory === '~' || directory.startsWith('~/'))) {
            throw new SshHostsError('INVALID_SERVICE', `${prefix} 服务 ${name} 的 directory 无效`, '请使用绝对路径或 ~/... 表示服务所在目录');
        }
        const description = optionalString(entry.description);
        const startCommand = optionalString(entry.startCommand);
        const logPath = optionalString(entry.logPath);
        let port;
        if (entry.port !== undefined && entry.port !== null) {
            if (typeof entry.port !== 'number' || !Number.isInteger(entry.port) || entry.port < 1 || entry.port > 65535) {
                throw new SshHostsError('INVALID_SERVICE', `${prefix} 服务 ${name} 的 port 无效`, '端口必须是 1-65535 的整数');
            }
            port = entry.port;
        }
        return {
            name,
            directory,
            ...(description === undefined ? {} : { description }),
            ...(startCommand === undefined ? {} : { startCommand }),
            ...(logPath === undefined ? {} : { logPath }),
            ...(port === undefined ? {} : { port }),
        };
    });
}
function validateAuth(value, index) {
    if (!isRecord(value)) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条缺少 auth`, '请检查该主机的认证配置');
    }
    if (value.type === 'password') {
        return { type: 'password', secretRef: requireString(value.secretRef, 'auth.secretRef', index) };
    }
    if (value.type === 'key') {
        const passphraseRef = optionalString(value.passphraseRef);
        return {
            type: 'key',
            privateKeyPath: requireString(value.privateKeyPath, 'auth.privateKeyPath', index),
            ...(passphraseRef === undefined ? {} : { passphraseRef }),
        };
    }
    throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条 auth.type 只能是 password 或 key`, '请检查该主机的认证配置');
}
/** Validate one persisted sudo policy; `undefined` means “not configured”. */
function validateSudoRecord(value, index) {
    if (value === undefined || value === null)
        return undefined;
    const prefix = `hosts.json 第 ${index + 1} 条的 sudo`;
    if (!isRecord(value)) {
        throw new SshHostsError('STORAGE_INVALID', `${prefix} 必须是对象`, '包含 mode（nopasswd 或 password）与可选 user');
    }
    const mode = value.mode;
    if (mode !== 'nopasswd' && mode !== 'password') {
        throw new SshHostsError('STORAGE_INVALID', `${prefix}.mode 无效：${String(mode)}`, '只能是 nopasswd 或 password');
    }
    const user = optionalString(value.user);
    if (user !== undefined && !SUDO_USER_PATTERN.test(user)) {
        throw new SshHostsError('STORAGE_INVALID', `${prefix}.user 无效：${user}`, '用户名只能包含字母、数字、下划线、点和连字符');
    }
    const passwordRef = optionalString(value.passwordRef);
    return {
        mode,
        ...(user === undefined ? {} : { user }),
        ...(passwordRef === undefined ? {} : { passwordRef }),
    };
}
/**
 * Turn one management/tool input into a stored policy.
 *
 * `mode: 'off'` (or no input) clears it. The credential reference is always
 * rewritten to the canonical `host:<id>:sudo` key so a host that is edited or
 * re-added can never point at another host's secret.
 */
export function normalizeSudoInput(input, hostId) {
    if (input === undefined || input.mode === 'off')
        return undefined;
    if (input.mode !== 'nopasswd' && input.mode !== 'password') {
        throw new SshHostsError('INVALID_SUDO', `sudo 模式无效：${String(input.mode)}`, '只能是 off、nopasswd 或 password');
    }
    const raw = input.user;
    const user = typeof raw === 'string' && raw.trim().length > 0 ? raw.trim() : undefined;
    if (user !== undefined && !SUDO_USER_PATTERN.test(user)) {
        throw new SshHostsError('INVALID_SUDO', `sudo 目标用户无效：${user}`, '用户名只能包含字母、数字、下划线、点和连字符');
    }
    return {
        mode: input.mode,
        ...(user === undefined ? {} : { user }),
        passwordRef: sudoPasswordRef(hostId),
    };
}
function sameSudo(left, right) {
    return (left?.mode ?? 'off') === (right?.mode ?? 'off') && (left?.user ?? null) === (right?.user ?? null);
}
/** Validate one persisted host and fill fields added by later versions. */
export function normalizeHost(value, index) {
    if (!isRecord(value)) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条不是对象`, '请检查该主机的配置');
    }
    const id = requireString(value.id, 'id', index);
    if (!/^[A-Za-z0-9_-]{3,64}$/.test(id)) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条的 id 无效：${id}`, 'id 只能包含字母、数字、下划线和连字符');
    }
    const alias = requireString(value.alias, 'alias', index);
    const host = requireString(value.host, 'host', index);
    const username = requireString(value.username, 'username', index);
    const port = typeof value.port === 'number' ? value.port : 22;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条的端口无效：${String(value.port)}`, '端口必须是 1-65535 的整数');
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(alias)) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条的别名无效：${alias}`, '别名只能包含字母、数字、点、下划线和连字符，且以字母或数字开头');
    }
    if (/[\s/]/.test(host)) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条的主机名无效：${host}`, '主机名不能包含空白或斜杠');
    }
    if (/[\s/]/.test(username)) {
        throw new SshHostsError('STORAGE_INVALID', `hosts.json 第 ${index + 1} 条的用户名无效：${username}`, '用户名不能包含空白或斜杠');
    }
    const fingerprintPolicy = value.fingerprintPolicy === 'accept-new' ? 'accept-new' : 'strict';
    let fingerprint = null;
    if (isRecord(value.fingerprint) && typeof value.fingerprint.sha256 === 'string') {
        fingerprint = {
            sha256: value.fingerprint.sha256,
            addedAt: typeof value.fingerprint.addedAt === 'string' ? value.fingerprint.addedAt : new Date(0).toISOString(),
        };
    }
    const now = new Date().toISOString();
    const sudo = validateSudoRecord(value.sudo, index);
    return {
        id,
        alias,
        host,
        port,
        username,
        auth: validateAuth(value.auth, index),
        fingerprint,
        fingerprintPolicy,
        ...(optionalString(value.defaultCwd) === undefined ? {} : { defaultCwd: optionalString(value.defaultCwd) }),
        allowedPaths: stringArray(value.allowedPaths, ['~'], 'allowedPaths', index),
        editablePaths: stringArray(value.editablePaths, [], 'editablePaths', index),
        services: validateServices(value.services, index),
        ...(sudo === undefined ? {} : { sudo }),
        deniedPaths: stringArray(value.deniedPaths, DEFAULT_DENIED_PATHS, 'deniedPaths', index),
        readOnly: value.readOnly === true,
        tags: stringArray(value.tags, [], 'tags', index),
        ...(optionalString(value.note) === undefined ? {} : { note: optionalString(value.note) }),
        createdAt: optionalString(value.createdAt) ?? now,
        updatedAt: optionalString(value.updatedAt) ?? now,
    };
}
function validateAlias(alias) {
    const trimmed = alias.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(trimmed)) {
        throw new SshHostsError('INVALID_ALIAS', `别名无效：${alias}`, '别名只能包含字母、数字、点、下划线和连字符，且以字母或数字开头');
    }
    return trimmed;
}
function validateHostName(host) {
    const trimmed = host.trim();
    if (trimmed.length === 0 || /[\s/]/.test(trimmed)) {
        throw new SshHostsError('INVALID_HOST', `主机名无效：${host}`, '请输入 IP 或域名，不能包含空白或斜杠');
    }
    return trimmed;
}
function validateUsername(username) {
    const trimmed = username.trim();
    if (trimmed.length === 0 || /[\s/]/.test(trimmed)) {
        throw new SshHostsError('INVALID_USER', `用户名无效：${username}`, '用户名不能包含空白或斜杠');
    }
    return trimmed;
}
function validatePort(port) {
    const value = port ?? 22;
    if (!Number.isInteger(value) || value < 1 || value > 65535) {
        throw new SshHostsError('INVALID_PORT', `端口无效：${port}`, '端口必须是 1-65535 的整数');
    }
    return value;
}
function validatePathList(value, field, allowEmpty) {
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string' || entry.trim().length === 0)) {
        throw new SshHostsError('INVALID_PATHS', `${field} 必须是非空字符串数组`, '每行填写一个远程路径，例如 ~ 或 ~/app');
    }
    const list = value.map((entry) => entry.trim());
    if (!allowEmpty && list.length === 0) {
        throw new SshHostsError('INVALID_PATHS', `${field} 不能为空`, `至少保留一个路径，例如 ~`);
    }
    return list;
}
/** Normalize a pre-trusted `SHA256:...` host-key fingerprint. */
function validateFingerprint(value) {
    if (value === undefined || value.trim().length === 0)
        return undefined;
    const trimmed = value.trim();
    const normalized = trimmed.startsWith('SHA256:') ? trimmed : `SHA256:${trimmed}`;
    if (!/^SHA256:[A-Za-z0-9+/]{43}=?$/.test(normalized)) {
        throw new SshHostsError('INVALID_FINGERPRINT', `主机密钥指纹格式无效：${value}`, '请提供 OpenSSH SHA256 指纹，例如 SHA256:0vWs8...');
    }
    return normalized;
}
/** Derive the redacted model-facing view; never includes key paths or secrets. */
export function toHostView(host, credentialStatus, sudoPasswordConfigured = false, tempDir = null) {
    return {
        id: host.id,
        alias: host.alias,
        host: host.host,
        port: host.port,
        username: host.username,
        authType: host.auth.type,
        hasFingerprint: host.fingerprint !== null,
        fingerprint: host.fingerprint?.sha256 ?? null,
        fingerprintPolicy: host.fingerprintPolicy,
        credentialStatus,
        privateKeyConfigured: host.auth.type === 'key',
        defaultCwd: host.defaultCwd ?? null,
        allowedPaths: [...host.allowedPaths],
        editablePaths: [...host.editablePaths],
        tempDir,
        services: host.services.map((service) => ({ ...service })),
        sudo: {
            mode: host.sudo?.mode ?? 'off',
            user: host.sudo?.user ?? null,
            passwordConfigured: host.sudo?.mode === 'password' ? sudoPasswordConfigured : false,
        },
        deniedPaths: [...host.deniedPaths],
        readOnly: host.readOnly,
        tags: [...host.tags],
        note: host.note ?? null,
        createdAt: host.createdAt,
        updatedAt: host.updatedAt,
    };
}
function sameStrings(left, right) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
}
/** The persisted host inventory. All mutations are serialized. */
export class HostStore {
    dataDir;
    file;
    cache = null;
    queue = Promise.resolve();
    constructor(dataDir) {
        this.dataDir = dataDir;
        this.file = join(dataDir, HOSTS_FILE);
    }
    /** Load once and cache; a manual edit becomes visible on restart or `reload`. */
    async load() {
        if (this.cache !== null)
            return this.cache;
        const document = await readJson(this.file);
        if (document === undefined) {
            this.cache = [];
            return this.cache;
        }
        const rawHosts = Array.isArray(document) ? document : Array.isArray(document.hosts) ? document.hosts : null;
        if (rawHosts === null) {
            throw new SshHostsError('STORAGE_INVALID', `hosts.json 缺少 hosts 数组：${this.file}`, '请修复该文件后重启 Harness');
        }
        const hosts = rawHosts.map((entry, index) => normalizeHost(entry, index));
        const ids = new Set();
        const aliases = new Set();
        for (const host of hosts) {
            if (ids.has(host.id))
                throw new SshHostsError('STORAGE_INVALID', `hosts.json 存在重复 id：${host.id}`, '每个主机的 id 必须唯一');
            if (aliases.has(host.alias))
                throw new SshHostsError('STORAGE_INVALID', `hosts.json 存在重复别名：${host.alias}`, '每个主机的别名必须唯一');
            ids.add(host.id);
            aliases.add(host.alias);
        }
        this.cache = hosts;
        return hosts;
    }
    /** All hosts in file order. */
    async list() {
        return [...(await this.load())];
    }
    /** Discard the cache so the next read re-parses hosts.json. */
    async reload() {
        this.cache = null;
        return this.load();
    }
    /** Find one host by id or alias; the error lists the available aliases. */
    async find(ref) {
        const hosts = await this.load();
        const host = hosts.find((entry) => entry.id === ref || entry.alias === ref);
        if (host === undefined) {
            const available = hosts.map((entry) => entry.alias).join('、') || '无';
            throw new SshHostsError('HOST_NOT_FOUND', `未找到主机：${ref}`, `现有主机：${available}`);
        }
        return host;
    }
    async add(input) {
        const alias = validateAlias(input.alias);
        const host = validateHostName(input.host);
        const username = validateUsername(input.username);
        const port = validatePort(input.port);
        if (input.authType !== 'password' && input.authType !== 'key') {
            throw new SshHostsError('INVALID_AUTH', `认证类型无效：${String(input.authType)}`, '认证类型只能是 password 或 key');
        }
        if (input.authType === 'key' && (input.privateKeyPath === undefined || input.privateKeyPath.trim().length === 0)) {
            throw new SshHostsError('INVALID_AUTH', '私钥认证缺少 privateKeyPath', '请提供服务器本机可读的私钥文件路径');
        }
        return this.mutate(async (hosts) => {
            if (hosts.some((entry) => entry.alias === alias)) {
                throw new SshHostsError('HOST_ALIAS_EXISTS', `别名已存在：${alias}`, '请换一个别名，或先更新/删除现有主机');
            }
            const id = `host_${randomBytes(4).toString('hex')}`;
            const now = new Date().toISOString();
            const auth = input.authType === 'password'
                ? { type: 'password', secretRef: `host:${id}:password` }
                : {
                    type: 'key',
                    privateKeyPath: input.privateKeyPath,
                    passphraseRef: `host:${id}:passphrase`,
                };
            const trustedFingerprint = validateFingerprint(input.hostKeyFingerprint);
            const sudo = normalizeSudoInput(input.sudo, id);
            const record = {
                id,
                alias,
                host,
                port,
                username,
                auth,
                fingerprint: trustedFingerprint === undefined
                    ? null
                    : { sha256: trustedFingerprint, addedAt: now },
                fingerprintPolicy: input.fingerprintPolicy === 'accept-new' ? 'accept-new' : 'strict',
                ...(input.defaultCwd === undefined ? {} : { defaultCwd: input.defaultCwd }),
                allowedPaths: input.allowedPaths !== undefined && input.allowedPaths.length > 0 ? input.allowedPaths : ['~'],
                editablePaths: input.editablePaths !== undefined ? [...input.editablePaths] : [],
                services: validateServices(input.services, null),
                ...(sudo === undefined ? {} : { sudo }),
                deniedPaths: [...DEFAULT_DENIED_PATHS],
                readOnly: input.readOnly === true,
                tags: input.tags ?? [],
                ...(input.note === undefined ? {} : { note: input.note }),
                createdAt: now,
                updatedAt: now,
            };
            hosts.push(record);
            await this.persist(hosts);
            return structuredClone(record);
        });
    }
    async update(ref, patch) {
        return this.mutate(async (hosts) => {
            const index = hosts.findIndex((entry) => entry.id === ref || entry.alias === ref);
            if (index < 0) {
                const available = hosts.map((entry) => entry.alias).join('、') || '无';
                throw new SshHostsError('HOST_NOT_FOUND', `未找到主机：${ref}`, `现有主机：${available}`);
            }
            const current = hosts[index];
            // Security-critical identity and policy fields are fixed after creation.
            // A model must not be able to point a stored password at another server,
            // widen the path allowlist, or turn off read-only/TOFU by editing metadata.
            if (patch.host !== undefined && validateHostName(patch.host) !== current.host) {
                throw new SshHostsError('HOST_IDENTITY_LOCKED', '主机地址不能在更新中修改', '请先删除该主机（会同时删除凭据）后重新添加，或由用户编辑 hosts.json');
            }
            if (patch.port !== undefined && validatePort(patch.port) !== current.port) {
                throw new SshHostsError('HOST_IDENTITY_LOCKED', 'SSH 端口不能在更新中修改', '请先删除该主机后重新添加，或由用户编辑 hosts.json');
            }
            if (patch.username !== undefined && validateUsername(patch.username) !== current.username) {
                throw new SshHostsError('HOST_IDENTITY_LOCKED', '登录用户不能在更新中修改', '请先删除该主机后重新添加，或由用户编辑 hosts.json');
            }
            if (patch.allowedPaths !== undefined && !sameStrings(patch.allowedPaths, current.allowedPaths)) {
                throw new SshHostsError('PATH_POLICY_LOCKED', 'allowedPaths 不能在更新中修改', '请由用户编辑 hosts.json；这是防止模型自行扩大可访问路径');
            }
            if (patch.editablePaths !== undefined && !sameStrings(patch.editablePaths, current.editablePaths)) {
                throw new SshHostsError('EDIT_POLICY_LOCKED', 'editablePaths 不能在更新中修改', '请由用户编辑 hosts.json；这是防止模型自行扩大可编辑目录');
            }
            if (patch.readOnly === false && current.readOnly) {
                throw new SshHostsError('READ_ONLY_LOCKED', '只读服务器不能由工具关闭只读', '请由用户编辑 hosts.json');
            }
            if (patch.sudo !== undefined) {
                // Root access is user-managed: a model must never be able to enable or
                // widen sudo on a host, even by passing the current value back.
                if (!sameSudo(normalizeSudoInput(patch.sudo, current.id), current.sudo)) {
                    throw new SshHostsError('SUDO_POLICY_LOCKED', 'sudo 提权策略不能由工具修改', '请由用户在 Web「SSH 服务器」页面或 hosts.json 中配置 sudo');
                }
            }
            if (patch.fingerprintPolicy === 'accept-new' && current.fingerprintPolicy === 'strict') {
                throw new SshHostsError('FINGERPRINT_POLICY_LOCKED', '不能由工具把主机密钥策略放宽为 accept-new', '请由用户编辑 hosts.json');
            }
            if (patch.privateKeyPath !== undefined) {
                const currentKeyPath = current.auth.type === 'key' ? current.auth.privateKeyPath : undefined;
                if (patch.privateKeyPath !== currentKeyPath) {
                    throw new SshHostsError('KEY_PATH_LOCKED', '私钥路径不能在更新中修改', '请由用户编辑 hosts.json，避免模型把认证指向其他本机密钥');
                }
            }
            const next = structuredClone(current);
            if (patch.alias !== undefined) {
                const alias = validateAlias(patch.alias);
                if (hosts.some((entry, entryIndex) => entryIndex !== index && entry.alias === alias)) {
                    throw new SshHostsError('HOST_ALIAS_EXISTS', `别名已存在：${alias}`, '请换一个别名');
                }
                next.alias = alias;
            }
            if (patch.host !== undefined)
                next.host = validateHostName(patch.host);
            if (patch.port !== undefined)
                next.port = validatePort(patch.port);
            if (patch.username !== undefined)
                next.username = validateUsername(patch.username);
            if (patch.defaultCwd !== undefined) {
                if (patch.defaultCwd === null)
                    delete next.defaultCwd;
                else
                    next.defaultCwd = patch.defaultCwd;
            }
            if (patch.allowedPaths !== undefined) {
                if (patch.allowedPaths.length === 0)
                    throw new SshHostsError('INVALID_PATHS', 'allowedPaths 不能为空', '至少保留一个可访问的远程目录，例如 ~');
                next.allowedPaths = [...patch.allowedPaths];
            }
            if (patch.tags !== undefined)
                next.tags = [...patch.tags];
            if (patch.services !== undefined)
                next.services = validateServices(patch.services, null);
            if (patch.note !== undefined) {
                if (patch.note === null)
                    delete next.note;
                else
                    next.note = patch.note;
            }
            if (patch.fingerprintPolicy !== undefined)
                next.fingerprintPolicy = patch.fingerprintPolicy;
            if (patch.readOnly !== undefined)
                next.readOnly = patch.readOnly;
            const nextAuthType = patch.authType ?? next.auth.type;
            if (nextAuthType !== 'password' && nextAuthType !== 'key') {
                throw new SshHostsError('INVALID_AUTH', `认证类型无效：${String(nextAuthType)}`, '认证类型只能是 password 或 key');
            }
            if (nextAuthType !== next.auth.type) {
                next.auth =
                    nextAuthType === 'password'
                        ? { type: 'password', secretRef: `host:${next.id}:password` }
                        : {
                            type: 'key',
                            privateKeyPath: patch.privateKeyPath ?? (next.auth.type === 'key' ? next.auth.privateKeyPath : ''),
                            passphraseRef: `host:${next.id}:passphrase`,
                        };
                if (next.auth.type === 'key' && next.auth.privateKeyPath.length === 0) {
                    throw new SshHostsError('INVALID_AUTH', '改为私钥认证时必须提供 privateKeyPath', '请提供服务器本机可读的私钥文件路径');
                }
            }
            else if (next.auth.type === 'key' && patch.privateKeyPath !== undefined) {
                next.auth = { ...next.auth, privateKeyPath: patch.privateKeyPath };
            }
            next.updatedAt = new Date().toISOString();
            hosts[index] = next;
            await this.persist(hosts);
            return structuredClone(next);
        });
    }
    async remove(ref) {
        return this.mutate(async (hosts) => {
            const index = hosts.findIndex((entry) => entry.id === ref || entry.alias === ref);
            if (index < 0) {
                const available = hosts.map((entry) => entry.alias).join('、') || '无';
                throw new SshHostsError('HOST_NOT_FOUND', `未找到主机：${ref}`, `现有主机：${available}`);
            }
            const [removed] = hosts.splice(index, 1);
            await this.persist(hosts);
            return structuredClone(removed);
        });
    }
    /**
     * Full user-initiated edit used by the local management page.
     *
     * The page is the human-facing counterpart of `ssh_host_update`: it may fix
     * the address, port, login user, auth type, key path, and path policy. All
     * values are still validated, and changing the connection identity drops the
     * old TOFU fingerprint unless the request pins a new one.
     */
    async updateManaged(ref, patch) {
        return this.mutate(async (hosts) => {
            const index = hosts.findIndex((entry) => entry.id === ref || entry.alias === ref);
            if (index < 0) {
                const available = hosts.map((entry) => entry.alias).join('、') || '无';
                throw new SshHostsError('HOST_NOT_FOUND', `未找到主机：${ref}`, `现有主机：${available}`);
            }
            const current = hosts[index];
            const next = structuredClone(current);
            const now = new Date().toISOString();
            let identityChanged = false;
            if (patch.alias !== undefined) {
                const alias = validateAlias(patch.alias);
                if (hosts.some((entry, entryIndex) => entryIndex !== index && entry.alias === alias)) {
                    throw new SshHostsError('HOST_ALIAS_EXISTS', `别名已存在：${alias}`, '请换一个别名');
                }
                next.alias = alias;
            }
            if (patch.host !== undefined) {
                const host = validateHostName(patch.host);
                if (host !== next.host)
                    identityChanged = true;
                next.host = host;
            }
            if (patch.port !== undefined) {
                const port = validatePort(patch.port);
                if (port !== next.port)
                    identityChanged = true;
                next.port = port;
            }
            if (patch.username !== undefined) {
                const username = validateUsername(patch.username);
                if (username !== next.username)
                    identityChanged = true;
                next.username = username;
            }
            if (patch.defaultCwd !== undefined) {
                if (patch.defaultCwd === null || patch.defaultCwd.trim().length === 0)
                    delete next.defaultCwd;
                else
                    next.defaultCwd = patch.defaultCwd.trim();
            }
            if (patch.allowedPaths !== undefined) {
                next.allowedPaths = validatePathList(patch.allowedPaths, 'allowedPaths', false);
            }
            if (patch.editablePaths !== undefined) {
                next.editablePaths = validatePathList(patch.editablePaths, 'editablePaths', true);
            }
            if (patch.tags !== undefined)
                next.tags = [...patch.tags];
            if (patch.services !== undefined)
                next.services = validateServices(patch.services, null);
            if (patch.note !== undefined) {
                if (patch.note === null || patch.note.trim().length === 0)
                    delete next.note;
                else
                    next.note = patch.note.trim();
            }
            if (patch.fingerprintPolicy !== undefined) {
                if (patch.fingerprintPolicy !== 'strict' && patch.fingerprintPolicy !== 'accept-new') {
                    throw new SshHostsError('INVALID_FINGERPRINT_POLICY', `指纹策略无效：${String(patch.fingerprintPolicy)}`, '只能是 strict 或 accept-new');
                }
                next.fingerprintPolicy = patch.fingerprintPolicy;
            }
            if (patch.readOnly !== undefined)
                next.readOnly = patch.readOnly;
            if (patch.sudo !== undefined) {
                const sudo = normalizeSudoInput(patch.sudo, next.id);
                if (sudo === undefined)
                    delete next.sudo;
                else
                    next.sudo = sudo;
            }
            const nextAuthType = patch.authType ?? next.auth.type;
            if (nextAuthType !== 'password' && nextAuthType !== 'key') {
                throw new SshHostsError('INVALID_AUTH', `认证类型无效：${String(nextAuthType)}`, '认证类型只能是 password 或 key');
            }
            if (nextAuthType === 'password') {
                if (patch.privateKeyPath !== undefined) {
                    throw new SshHostsError('INVALID_AUTH', '密码认证不能设置 privateKeyPath', '请切回密码认证并留空私钥路径');
                }
                if (next.auth.type !== 'password') {
                    next.auth = { type: 'password', secretRef: `host:${next.id}:password` };
                }
            }
            else {
                const keyPath = patch.privateKeyPath?.trim() ?? (next.auth.type === 'key' ? next.auth.privateKeyPath : '');
                if (keyPath.length === 0) {
                    throw new SshHostsError('INVALID_AUTH', '私钥认证缺少 privateKeyPath', '请填写服务器本机可读的私钥文件路径');
                }
                if (next.auth.type !== 'key' || next.auth.privateKeyPath !== keyPath) {
                    next.auth = { type: 'key', privateKeyPath: keyPath, passphraseRef: `host:${next.id}:passphrase` };
                }
            }
            if (patch.hostKeyFingerprint !== undefined) {
                if (patch.hostKeyFingerprint === null || patch.hostKeyFingerprint.trim().length === 0) {
                    next.fingerprint = null;
                }
                else {
                    next.fingerprint = { sha256: validateFingerprint(patch.hostKeyFingerprint), addedAt: now };
                }
            }
            else if (identityChanged) {
                // The old key belonged to the old address/user; do not fail the next
                // connection against a fingerprint from another endpoint.
                next.fingerprint = null;
            }
            next.updatedAt = now;
            hosts[index] = next;
            await this.persist(hosts);
            return structuredClone(next);
        });
    }
    /** Persist a TOFU fingerprint after the first successful handshake. */
    async setFingerprint(id, sha256) {
        await this.mutate(async (hosts) => {
            const host = hosts.find((entry) => entry.id === id);
            if (host === undefined)
                throw new SshHostsError('HOST_NOT_FOUND', `未找到主机：${id}`, '主机可能在连接期间被删除');
            host.fingerprint = { sha256, addedAt: new Date().toISOString() };
            host.updatedAt = new Date().toISOString();
            await this.persist(hosts);
        });
    }
    async mutate(fn) {
        const run = this.queue.then(async () => {
            const hosts = structuredClone(await this.load());
            return fn(hosts);
        });
        this.queue = run.catch(() => undefined);
        return run;
    }
    async persist(hosts) {
        const document = { version: 1, hosts };
        await atomicWriteFile(this.file, `${JSON.stringify(document, null, 2)}\n`);
        this.cache = structuredClone(hosts);
    }
}
