/**
 * Local server-management API behind the Web "SSH 服务器" page.
 *
 * This is the human-facing counterpart of the `ssh_host_*` tools: it can add,
 * fully edit, remove, test, and provision credentials for a host. It is mounted
 * at `/ssh-hosts-ui` on the Harness web server and is deliberately limited to
 * loopback clients; write requests must also carry the page's custom header and
 * a same-machine Origin, which keeps ordinary cross-site requests out.
 *
 * Passwords and key passphrases may be submitted here. They are written only to
 * the encrypted credential store, never returned, audited, or logged.
 */
import { configuredTempDir } from './config.js';
import { pathExists } from './fs-util.js';
import { toHostView, validateServices } from './hosts.js';
import { envNameFor } from './secrets.js';
import { sudoPasswordRef, sudoPasswordStatus, sudoSecretRef } from './sudo.js';
import { SshHostsError } from './types.js';
import { hasUiWriteHeader, isLoopbackOrigin, isLoopbackRequest, readJsonBody, registerPrefixRoute, sendError, sendJson, statusForError, } from './web.js';
/** URL prefix this API claims on the Harness web server. */
export const ROUTE_PREFIX = '/ssh-hosts-ui';
async function credentialStatusOf(host, options) {
    if (host.auth.type === 'password')
        return options.secrets.status(host.auth.secretRef);
    return (await pathExists(host.auth.privateKeyPath)) ? 'available' : 'missing';
}
function nextStepFor(host, status, options) {
    if (status !== 'available') {
        if (options.config.secretsBackend === 'env') {
            const ref = host.auth.type === 'password' ? host.auth.secretRef : host.auth.passphraseRef;
            const name = ref === undefined ? '' : envNameFor(ref, options.config.envPrefix);
            return `凭据来自环境变量：请在本机设置 ${name} 后重启 Harness。`;
        }
        return host.auth.type === 'password'
            ? '尚未保存密码：可在此页面重新填写并保存。'
            : '本机读不到该私钥文件：请检查 privateKeyPath，或改用密码认证。';
    }
    if (host.sudo?.mode === 'password') {
        const ref = sudoSecretRef(host) ?? sudoPasswordRef(host.id);
        if (options.config.secretsBackend === 'env') {
            return `sudo 使用密码模式：请在本机设置 ${envNameFor(ref, options.config.envPrefix)} 后重启 Harness，或改用 NOPASSWD。`;
        }
    }
    if (host.editablePaths.length === 0) {
        return configuredTempDir(options.config) === null
            ? '未配置 editablePaths：Agent 只能读取/下载，不能写入或上传。'
            : `未配置 editablePaths：Agent 只能读取/下载；写入仅限插件默认授予读写的临时目录 ${configuredTempDir(options.config)}（tempDir）。`;
    }
    return null;
}
function meta(options) {
    return {
        backend: options.config.secretsBackend,
        envPrefix: options.config.envPrefix,
        dataDir: options.dataDir,
        auditEnabled: options.config.audit,
    };
}
async function viewOf(host, options) {
    const credentialStatus = await credentialStatusOf(host, options);
    const sudo = await sudoPasswordStatus(options, host);
    return { host: toHostView(host, credentialStatus, sudo === 'available', configuredTempDir(options.config)), credentialStatus };
}
// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------
function has(body, key) {
    return Object.prototype.hasOwnProperty.call(body, key);
}
function requiredString(body, key) {
    const value = body[key];
    if (typeof value !== 'string') {
        throw new SshHostsError('INVALID_BODY', `字段 ${key} 必须是字符串`, '请刷新页面后重试');
    }
    return value.trim();
}
function optionalString(body, key) {
    if (!has(body, key))
        return undefined;
    const value = body[key];
    if (value === undefined || value === null)
        return undefined;
    if (typeof value !== 'string') {
        throw new SshHostsError('INVALID_BODY', `字段 ${key} 必须是字符串`, '请刷新页面后重试');
    }
    const trimmed = value.trim();
    return trimmed.length === 0 ? undefined : trimmed;
}
/** `null` (or an empty string) explicitly clears the field; absent keeps it. */
function optionalNullableString(body, key) {
    if (!has(body, key))
        return undefined;
    const value = body[key];
    if (value === undefined || value === null)
        return null;
    if (typeof value !== 'string') {
        throw new SshHostsError('INVALID_BODY', `字段 ${key} 必须是字符串或 null`, '请刷新页面后重试');
    }
    const trimmed = value.trim();
    return trimmed.length === 0 ? null : trimmed;
}
function optionalInt(body, key) {
    if (!has(body, key))
        return undefined;
    const value = body[key];
    if (value === undefined || value === null)
        return undefined;
    if (typeof value !== 'number' || !Number.isInteger(value)) {
        throw new SshHostsError('INVALID_BODY', `字段 ${key} 必须是整数`, '端口请填写 1-65535 的整数');
    }
    return value;
}
function optionalBool(body, key) {
    if (!has(body, key))
        return undefined;
    const value = body[key];
    if (value === undefined || value === null)
        return undefined;
    if (typeof value !== 'boolean') {
        throw new SshHostsError('INVALID_BODY', `字段 ${key} 必须是布尔值`, '请刷新页面后重试');
    }
    return value;
}
function optionalStringArray(body, key) {
    if (!has(body, key))
        return undefined;
    const value = body[key];
    if (value === undefined || value === null)
        return undefined;
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string' || entry.trim().length === 0)) {
        throw new SshHostsError('INVALID_BODY', `${key} 必须是非空字符串数组`, '每行填写一个值');
    }
    return value.map((entry) => entry.trim());
}
/** A secret is never trimmed: leading/trailing spaces can be meaningful. */
function optionalSecret(body, key) {
    if (!has(body, key))
        return undefined;
    const value = body[key];
    if (value === undefined || value === null)
        return undefined;
    if (typeof value !== 'string') {
        throw new SshHostsError('INVALID_BODY', `字段 ${key} 必须是字符串`, '请刷新页面后重试');
    }
    if (value.length === 0)
        return undefined;
    if (value.length > 4096) {
        throw new SshHostsError('INVALID_SECRET', '密码或口令过长', '请确认输入内容（上限 4096 字符）');
    }
    return value;
}
function optionalServices(body) {
    if (!has(body, 'services'))
        return undefined;
    return validateServices(body.services, null);
}
function optionalFingerprintPolicy(body) {
    const value = optionalString(body, 'fingerprintPolicy');
    if (value === undefined)
        return undefined;
    if (value !== 'strict' && value !== 'accept-new') {
        throw new SshHostsError('INVALID_FINGERPRINT_POLICY', `指纹策略无效：${value}`, '只能是 strict 或 accept-new');
    }
    return value;
}
function optionalAuthType(body) {
    const value = optionalString(body, 'authType');
    if (value === undefined)
        return undefined;
    if (value !== 'password' && value !== 'key') {
        throw new SshHostsError('INVALID_AUTH', `认证类型无效：${value}`, '只能是 password 或 key');
    }
    return value;
}
/**
 * Parse the optional `sudo` object of a create/update payload.
 *
 * Shape: `{ mode: 'off' | 'nopasswd' | 'password', user?: string, password?: string }`.
 * The password is a write-only convenience: it is stored in the encrypted
 * credential store under `host:<id>:sudo` and never returned.
 */
function parseSudo(body) {
    if (!has(body, 'sudo'))
        return undefined;
    const value = body.sudo;
    if (value === null)
        return { policy: { mode: 'off' }, password: undefined };
    if (typeof value !== 'object' || Array.isArray(value)) {
        throw new SshHostsError('INVALID_BODY', 'sudo 必须是对象或 null', '包含 mode（off/nopasswd/password）、可选 user 与 password');
    }
    const record = value;
    const mode = record.mode;
    if (mode !== 'off' && mode !== 'nopasswd' && mode !== 'password') {
        throw new SshHostsError('INVALID_SUDO', `sudo 模式无效：${String(mode)}`, '只能是 off、nopasswd 或 password');
    }
    const user = optionalString(record, 'user');
    const password = optionalSecret(record, 'password');
    if (mode !== 'password' && password !== undefined) {
        throw new SshHostsError('INVALID_SUDO', '只有密码模式才能填写 sudo 密码', '请把 sudo 模式改为 password，或清空密码');
    }
    return {
        policy: { mode, ...(user === undefined ? {} : { user }) },
        password,
    };
}
function parseCreate(body) {
    const alias = requiredString(body, 'alias');
    const host = requiredString(body, 'host');
    const username = requiredString(body, 'username');
    const authType = optionalAuthType(body);
    if (authType === undefined) {
        throw new SshHostsError('INVALID_BODY', '缺少字段 authType', '认证方式只能是 password 或 key');
    }
    const input = { alias, host, username, authType };
    const sudo = parseSudo(body);
    let sudoPassword;
    if (sudo !== undefined) {
        input.sudo = sudo.policy;
        sudoPassword = sudo.password;
    }
    const port = optionalInt(body, 'port');
    if (port !== undefined)
        input.port = port;
    const privateKeyPath = optionalString(body, 'privateKeyPath');
    if (privateKeyPath !== undefined)
        input.privateKeyPath = privateKeyPath;
    const defaultCwd = optionalNullableString(body, 'defaultCwd');
    if (defaultCwd !== undefined && defaultCwd !== null)
        input.defaultCwd = defaultCwd;
    const allowedPaths = optionalStringArray(body, 'allowedPaths');
    if (allowedPaths !== undefined)
        input.allowedPaths = allowedPaths;
    const editablePaths = optionalStringArray(body, 'editablePaths');
    if (editablePaths !== undefined)
        input.editablePaths = editablePaths;
    const services = optionalServices(body);
    if (services !== undefined)
        input.services = services;
    const tags = optionalStringArray(body, 'tags');
    if (tags !== undefined)
        input.tags = tags;
    const note = optionalNullableString(body, 'note');
    if (note !== undefined && note !== null)
        input.note = note;
    const hostKeyFingerprint = optionalString(body, 'hostKeyFingerprint');
    if (hostKeyFingerprint !== undefined)
        input.hostKeyFingerprint = hostKeyFingerprint;
    const fingerprintPolicy = optionalFingerprintPolicy(body);
    if (fingerprintPolicy !== undefined)
        input.fingerprintPolicy = fingerprintPolicy;
    const readOnly = optionalBool(body, 'readOnly');
    if (readOnly !== undefined)
        input.readOnly = readOnly;
    const password = optionalSecret(body, 'password');
    const passphrase = optionalSecret(body, 'passphrase');
    if (password !== undefined && authType !== 'password') {
        throw new SshHostsError('INVALID_AUTH', '密码认证才能填写密码', '请把认证方式改为密码');
    }
    if (passphrase !== undefined && authType !== 'key') {
        throw new SshHostsError('INVALID_AUTH', '私钥认证才能填写私钥口令', '请把认证方式改为私钥');
    }
    return { input, password, passphrase, sudoPassword };
}
function parseUpdate(body) {
    const patch = {};
    const sudo = parseSudo(body);
    let sudoPassword;
    if (sudo !== undefined) {
        patch.sudo = sudo.policy;
        sudoPassword = sudo.password;
    }
    if (has(body, 'alias'))
        patch.alias = requiredString(body, 'alias');
    if (has(body, 'host'))
        patch.host = requiredString(body, 'host');
    if (has(body, 'username'))
        patch.username = requiredString(body, 'username');
    if (has(body, 'port')) {
        const port = optionalInt(body, 'port');
        if (port === undefined)
            throw new SshHostsError('INVALID_BODY', 'port 必须是整数', '端口请填写 1-65535 的整数');
        patch.port = port;
    }
    if (has(body, 'authType')) {
        const authType = optionalAuthType(body);
        if (authType === undefined)
            throw new SshHostsError('INVALID_AUTH', '认证类型无效', '只能是 password 或 key');
        patch.authType = authType;
    }
    if (has(body, 'privateKeyPath')) {
        const privateKeyPath = optionalString(body, 'privateKeyPath');
        if (privateKeyPath === undefined) {
            throw new SshHostsError('INVALID_AUTH', 'privateKeyPath 不能为空', '请填写服务器本机可读的私钥文件路径');
        }
        patch.privateKeyPath = privateKeyPath;
    }
    if (has(body, 'defaultCwd'))
        patch.defaultCwd = optionalNullableString(body, 'defaultCwd') ?? null;
    if (has(body, 'allowedPaths'))
        patch.allowedPaths = optionalStringArray(body, 'allowedPaths') ?? [];
    if (has(body, 'editablePaths'))
        patch.editablePaths = optionalStringArray(body, 'editablePaths') ?? [];
    if (has(body, 'services')) {
        const services = optionalServices(body);
        if (services !== undefined)
            patch.services = services;
    }
    if (has(body, 'tags'))
        patch.tags = optionalStringArray(body, 'tags') ?? [];
    if (has(body, 'note'))
        patch.note = optionalNullableString(body, 'note') ?? null;
    if (has(body, 'fingerprintPolicy')) {
        const policy = optionalFingerprintPolicy(body);
        if (policy !== undefined)
            patch.fingerprintPolicy = policy;
    }
    if (has(body, 'readOnly')) {
        const readOnly = optionalBool(body, 'readOnly');
        if (readOnly !== undefined)
            patch.readOnly = readOnly;
    }
    if (has(body, 'hostKeyFingerprint')) {
        patch.hostKeyFingerprint = optionalNullableString(body, 'hostKeyFingerprint') ?? null;
    }
    return {
        patch,
        password: optionalSecret(body, 'password'),
        passphrase: optionalSecret(body, 'passphrase'),
        sudoPassword,
    };
}
// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------
function assertLoopback(req) {
    if (!isLoopbackRequest(req)) {
        throw new SshHostsError('FORBIDDEN', '该接口只允许本机访问', '请在本机的 DSH 页面中打开');
    }
}
function assertWrite(req) {
    if (!hasUiWriteHeader(req)) {
        throw new SshHostsError('FORBIDDEN', '写操作需要来自 SSH 服务器页面的请求', '请刷新 SSH 服务器页面后重试');
    }
    const origin = Array.isArray(req.headers.origin) ? req.headers.origin[0] : req.headers.origin;
    if (origin !== undefined && !isLoopbackOrigin(origin)) {
        throw new SshHostsError('FORBIDDEN', '拒绝跨站写请求', '请在本机的 DSH 页面中操作');
    }
}
function assertSecretsWritable(password, passphrase, config) {
    if (password === undefined && passphrase === undefined)
        return;
    if (config.secretsBackend === 'env') {
        throw new SshHostsError('SECRET_ENV_READONLY', '当前凭据后端是 env，不会把密码写入磁盘', `请设置对应的环境变量（前缀 ${config.envPrefix}）后重启 Harness，或把 secretsBackend 改为 file`);
    }
    if (config.secretsBackend === 'none') {
        throw new SshHostsError('SECRET_BACKEND_NONE', '当前凭据后端是 none，不能保存密码', '请把 secretsBackend 改为 file');
    }
}
function methodNotAllowed(allow) {
    return new SshHostsError('METHOD_NOT_ALLOWED', '请求方法不支持', `允许的方法：${allow}`);
}
async function listHosts(res, options) {
    const hosts = await options.store.list();
    const views = [];
    for (const host of hosts)
        views.push((await viewOf(host, options)).host);
    sendJson(res, 200, {
        hosts: views,
        count: views.length,
        ...meta(options),
        generatedAt: new Date().toISOString(),
    });
}
async function getHost(res, id, options) {
    const host = await options.store.find(id);
    const view = await viewOf(host, options);
    sendJson(res, 200, {
        host: view.host,
        credentialStatus: view.credentialStatus,
        nextStep: nextStepFor(host, view.credentialStatus, options),
        ...meta(options),
    });
}
async function createHost(req, res, options) {
    assertWrite(req);
    const body = await readJsonBody(req);
    const request = parseCreate(body);
    assertSecretsWritable(request.password, request.passphrase, options.config);
    assertSecretsWritable(request.sudoPassword, undefined, options.config);
    const record = await options.store.add(request.input);
    try {
        if (request.password !== undefined && record.auth.type === 'password') {
            await options.secrets.set(record.auth.secretRef, request.password);
        }
        if (request.passphrase !== undefined && record.auth.type === 'key' && record.auth.passphraseRef !== undefined) {
            await options.secrets.set(record.auth.passphraseRef, request.passphrase);
        }
        if (request.sudoPassword !== undefined && record.sudo?.mode === 'password') {
            await options.secrets.set(sudoSecretRef(record) ?? sudoPasswordRef(record.id), request.sudoPassword);
        }
    }
    catch (error) {
        // Do not leave a half-created host or orphaned credentials behind when the
        // credential write fails.
        await options.secrets.deleteHost(record.id).catch(() => undefined);
        await options.store.remove(record.id).catch(() => undefined);
        throw error;
    }
    const view = await viewOf(record, options);
    await options.audit.append({ action: 'host_add', server: record.alias, hostId: record.id, user: record.username, ok: true });
    options.debug(`ui added host ${record.alias} (${record.id}) credentials=${view.credentialStatus}`);
    sendJson(res, 201, {
        host: view.host,
        credentialStatus: view.credentialStatus,
        nextStep: nextStepFor(record, view.credentialStatus, options),
        ...meta(options),
    });
}
async function updateHost(req, res, id, options) {
    assertWrite(req);
    const body = await readJsonBody(req);
    const request = parseUpdate(body);
    assertSecretsWritable(request.password, request.passphrase, options.config);
    assertSecretsWritable(request.sudoPassword, undefined, options.config);
    const record = await options.store.updateManaged(id, request.patch);
    if (request.password !== undefined) {
        if (record.auth.type !== 'password') {
            throw new SshHostsError('INVALID_AUTH', '当前不是密码认证，不能保存密码', '请把认证方式改为密码');
        }
        await options.secrets.set(record.auth.secretRef, request.password);
    }
    if (request.passphrase !== undefined) {
        if (record.auth.type !== 'key' || record.auth.passphraseRef === undefined) {
            throw new SshHostsError('INVALID_AUTH', '当前不是私钥认证，不能保存私钥口令', '请把认证方式改为私钥');
        }
        await options.secrets.set(record.auth.passphraseRef, request.passphrase);
    }
    if (request.patch.sudo !== undefined) {
        const ref = `host:${record.id}:sudo`;
        if (record.sudo?.mode === 'password') {
            if (request.sudoPassword !== undefined)
                await options.secrets.set(ref, request.sudoPassword);
        }
        else {
            // Switching to off/nopasswd must not leave a stale password behind.
            await options.secrets.delete(ref);
        }
    }
    const view = await viewOf(record, options);
    await options.audit.append({ action: 'host_update', server: record.alias, hostId: record.id, user: record.username, ok: true });
    options.debug(`ui updated host ${record.alias} (${record.id})`);
    sendJson(res, 200, {
        host: view.host,
        credentialStatus: view.credentialStatus,
        nextStep: nextStepFor(record, view.credentialStatus, options),
        ...meta(options),
    });
}
async function removeHost(req, res, id, options) {
    assertWrite(req);
    const removed = await options.store.remove(id);
    const credentialsDeleted = await options.secrets.deleteHost(removed.id);
    await options.audit.append({ action: 'host_remove', server: removed.alias, hostId: removed.id, user: removed.username, ok: true });
    options.debug(`ui removed host ${removed.alias} (${removed.id}) credentials=${credentialsDeleted}`);
    sendJson(res, 200, { removed: true, id: removed.id, alias: removed.alias, credentialsDeleted });
}
async function setCredential(req, res, id, options) {
    assertWrite(req);
    const body = await readJsonBody(req);
    const kind = body.kind === 'passphrase' ? 'passphrase' : body.kind === 'password' ? 'password' : body.kind === 'sudo' ? 'sudo' : undefined;
    if (kind === undefined) {
        throw new SshHostsError('INVALID_BODY', '凭据类型无效', '只能是 password、passphrase 或 sudo');
    }
    const value = optionalSecret(body, 'value');
    if (value === undefined) {
        throw new SshHostsError('SECRET_EMPTY', '凭据不能为空', '请填写密码、私钥口令或 sudo 密码');
    }
    assertSecretsWritable(kind === 'password' || kind === 'sudo' ? value : undefined, kind === 'passphrase' ? value : undefined, options.config);
    const host = await options.store.find(id);
    let ref;
    if (kind === 'password') {
        if (host.auth.type !== 'password') {
            throw new SshHostsError('INVALID_AUTH', '当前不是密码认证', '请先切换认证方式');
        }
        ref = host.auth.secretRef;
    }
    else if (kind === 'passphrase') {
        if (host.auth.type !== 'key' || host.auth.passphraseRef === undefined) {
            throw new SshHostsError('INVALID_AUTH', '当前不是私钥认证', '请先切换认证方式');
        }
        ref = host.auth.passphraseRef;
    }
    else {
        if (host.sudo?.mode !== 'password') {
            throw new SshHostsError('INVALID_SUDO', '该主机没有启用 sudo 密码模式', '请先把 sudo 模式设为 password');
        }
        ref = sudoSecretRef(host) ?? sudoPasswordRef(host.id);
    }
    await options.secrets.set(ref, value);
    await options.audit.append({
        action: 'credential',
        server: host.alias,
        hostId: host.id,
        user: host.username,
        ok: true,
        code: kind,
    });
    sendJson(res, 200, { ok: true, kind, credentialStatus: 'available' });
}
async function clearCredential(req, res, id, url, options) {
    assertWrite(req);
    const kind = url.searchParams.get('kind') ?? 'password';
    if (kind !== 'password' && kind !== 'passphrase' && kind !== 'sudo' && kind !== 'all') {
        throw new SshHostsError('INVALID_BODY', '凭据类型无效', '只能是 password、passphrase、sudo 或 all');
    }
    const host = await options.store.find(id);
    let deleted = 0;
    if (kind === 'all') {
        deleted = await options.secrets.deleteHost(host.id);
    }
    else {
        const ref = `host:${host.id}:${kind}`;
        deleted = (await options.secrets.delete(ref)) ? 1 : 0;
    }
    if (deleted > 0) {
        await options.audit.append({
            action: 'credential',
            server: host.alias,
            hostId: host.id,
            user: host.username,
            ok: true,
            code: `clear-${kind}`,
        });
    }
    sendJson(res, 200, { ok: true, kind, deleted });
}
async function testHost(req, res, id, options) {
    assertWrite(req);
    const host = await options.store.find(id);
    const result = await options.manager.test(host);
    await options.audit.append({
        action: 'test',
        server: host.alias,
        hostId: host.id,
        user: host.username,
        ok: result.error === null,
        ...(result.error === null ? {} : { code: result.error.code }),
        durationMs: result.durationMs,
    });
    const view = await viewOf(host, options);
    sendJson(res, 200, { ...result, credentialStatus: view.credentialStatus });
}
/**
 * Build the request handler. Exported so tests can drive it without Cordis.
 */
export function createHostsUiHandler(options) {
    return async (req, res) => {
        try {
            assertLoopback(req);
            const url = new URL(req.url ?? ROUTE_PREFIX, 'http://127.0.0.1');
            const pathname = url.pathname.replace(/\/+$/, '') || ROUTE_PREFIX;
            if (pathname === `${ROUTE_PREFIX}/health`) {
                sendJson(res, 200, { ok: true, ...meta(options) });
                return;
            }
            if (pathname === `${ROUTE_PREFIX}/hosts`) {
                if (req.method === 'GET' || req.method === 'HEAD') {
                    await listHosts(res, options);
                    return;
                }
                if (req.method === 'POST') {
                    await createHost(req, res, options);
                    return;
                }
                throw methodNotAllowed('GET, POST');
            }
            const hostPrefix = `${ROUTE_PREFIX}/hosts/`;
            if (pathname.startsWith(hostPrefix)) {
                const parts = pathname.slice(hostPrefix.length).split('/').filter((part) => part.length > 0);
                if (parts.length === 0 || parts.length > 2) {
                    throw new SshHostsError('NOT_FOUND', '未知端点', '可用端点：/ssh-hosts-ui/hosts');
                }
                let id;
                try {
                    id = decodeURIComponent(parts[0]);
                }
                catch {
                    throw new SshHostsError('INVALID_BODY', '主机 id 编码无效', '请刷新页面后重试');
                }
                const action = parts[1];
                if (action === undefined) {
                    if (req.method === 'GET' || req.method === 'HEAD') {
                        await getHost(res, id, options);
                        return;
                    }
                    if (req.method === 'PATCH' || req.method === 'PUT') {
                        await updateHost(req, res, id, options);
                        return;
                    }
                    if (req.method === 'DELETE') {
                        await removeHost(req, res, id, options);
                        return;
                    }
                    throw methodNotAllowed('GET, PATCH, DELETE');
                }
                if (action === 'credential') {
                    if (req.method === 'PUT' || req.method === 'POST') {
                        await setCredential(req, res, id, options);
                        return;
                    }
                    if (req.method === 'DELETE') {
                        await clearCredential(req, res, id, url, options);
                        return;
                    }
                    throw methodNotAllowed('PUT, DELETE');
                }
                if (action === 'test') {
                    if (req.method === 'POST') {
                        await testHost(req, res, id, options);
                        return;
                    }
                    throw methodNotAllowed('POST');
                }
            }
            throw new SshHostsError('NOT_FOUND', '未知端点', '可用端点：/ssh-hosts-ui/hosts');
        }
        catch (error) {
            sendError(res, statusForError(error), error);
        }
    };
}
/** Register the management API once the Harness web server is available. */
export function registerHostsUiRoute(ctx, options) {
    registerPrefixRoute(ctx, {
        dataDir: options.dataDir,
        path: ROUTE_PREFIX,
        name: 'hosts-ui',
        statusFile: 'ui-route.json',
        debug: options.debug,
        handler: createHostsUiHandler(options),
    });
}
