/** Host inventory tools: add, list, update, remove, and connectivity test. */
import { defineTool } from '@deepseek-ai/dsh-tools';
import { configuredTempDir } from '../config.js';
import { pathExists } from '../fs-util.js';
import { sudoPasswordStatus } from '../sudo.js';
import { toHostView } from '../hosts.js';
const SERVICE_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: {
        name: { type: 'string', required: true, description: 'Service name, e.g. api, worker, db.' },
        directory: { type: 'string', required: true, description: 'Directory the service lives in (absolute or ~/...).' },
        description: { type: 'string', description: 'What the service does, or a warning for the Agent.' },
        startCommand: { type: 'string', description: 'How to start/restart it, e.g. systemctl restart api.' },
        logPath: { type: 'string', description: 'Log file or directory.' },
        port: { type: 'integer', description: 'Local listening port.' },
    },
};
const HOST_VIEW_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: {
        id: { type: 'string', required: true },
        alias: { type: 'string', required: true },
        host: { type: 'string', required: true },
        port: { type: 'integer', required: true },
        username: { type: 'string', required: true },
        authType: { type: 'string', required: true, enum: ['password', 'key'] },
        hasFingerprint: { type: 'boolean', required: true },
        fingerprint: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
        fingerprintPolicy: { type: 'string', required: true, enum: ['strict', 'accept-new'] },
        credentialStatus: { type: 'string', required: true, enum: ['available', 'missing', 'unavailable'] },
        privateKeyConfigured: { type: 'boolean', required: true },
        defaultCwd: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
        allowedPaths: { type: 'array', required: true, items: { type: 'string' } },
        editablePaths: { type: 'array', required: true, items: { type: 'string' } },
        tempDir: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
        services: { type: 'array', required: true, items: SERVICE_SCHEMA },
        sudo: {
            type: 'object',
            required: true,
            additionalProperties: false,
            properties: {
                mode: { type: 'string', required: true, enum: ['off', 'nopasswd', 'password'] },
                user: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                passwordConfigured: { type: 'boolean', required: true },
            },
        },
        deniedPaths: { type: 'array', required: true, items: { type: 'string' } },
        readOnly: { type: 'boolean', required: true },
        tags: { type: 'array', required: true, items: { type: 'string' } },
        note: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
        createdAt: { type: 'string', required: true },
        updatedAt: { type: 'string', required: true },
    },
};
async function credentialStatusOf(host, deps) {
    if (host.auth.type === 'password')
        return deps.secrets.status(host.auth.secretRef);
    return (await pathExists(host.auth.privateKeyPath)) ? 'available' : 'missing';
}
/** Build the redacted view, including whether a sudo password is available. */
async function viewOf(host, deps) {
    const status = await credentialStatusOf(host, deps);
    const sudo = await sudoPasswordStatus(deps, host);
    return toHostView(host, status, sudo === 'available', configuredTempDir(deps.config));
}
function credentialHint(host, status) {
    if (status !== 'missing')
        return null;
    if (host.auth.type === 'password') {
        return `尚未录入密码。请由用户在本机运行插件自带的 scripts/dsh-ssh.mjs set ${host.alias} --password（或设置环境变量），模型不会接收密码。`;
    }
    return `本机找不到私钥文件，或私钥受口令保护但尚未录入口令。请由用户确认 privateKeyPath，并用 scripts/dsh-ssh.mjs set ${host.alias} --passphrase 录入（如需要）。`;
}
/** Actionable follow-ups after add/update: credential, edit policy, service map. */
function operationalHints(host, status, tempDir) {
    const hints = [];
    const credential = credentialHint(host, status);
    if (credential !== null)
        hints.push(credential);
    if (host.editablePaths.length === 0) {
        hints.push(tempDir === null
            ? `未配置 editablePaths：Agent 只能读取/下载，不能写入或上传。如需编辑，请由用户编辑 hosts.json 的 editablePaths（建议只填服务目录，如 "~/app"）。`
            : `未配置 editablePaths：除临时目录 ${tempDir}（默认可读写）外，Agent 不能写入。如需编辑服务文件，请由用户编辑 hosts.json 的 editablePaths（建议只填服务目录，如 "~/app"）。`);
    }
    if (host.services.length === 0) {
        hints.push('尚未声明 services：请补充每个服务的 name 与 directory，后续 Agent 可用 ssh_services 直接定位服务目录。');
    }
    if (host.sudo?.mode === 'password') {
        hints.push(`该主机的 sudo 为密码模式：请由用户运行 scripts/dsh-ssh.mjs set ${host.alias} --sudo 录入 sudo 密码（或在 Web「SSH 服务器」页面填写）；未单独录入时会回退到 SSH 登录密码。`);
    }
    return hints.length === 0 ? null : hints.join(' ');
}
function renderHost(host) {
    const fingerprint = host.fingerprint ?? '未记录（首次连接时按 fingerprintPolicy 处理）';
    const lines = [
        `${host.alias}  ${host.username}@${host.host}:${host.port}`,
        `  id: ${host.id}`,
        `  认证: ${host.authType}  凭据: ${host.credentialStatus}  指纹: ${fingerprint}`,
        `  指纹策略: ${host.fingerprintPolicy}  只读: ${host.readOnly ? '是' : '否'}`,
        `  sudo: ${host.sudo.mode === 'off'
            ? '未配置（不能提权执行）'
            : `${host.sudo.mode === 'nopasswd' ? 'NOPASSWD' : '密码模式'} → ${host.sudo.user ?? 'root'}${host.sudo.mode === 'password'
                ? host.sudo.passwordConfigured
                    ? '（已录入 sudo 密码）'
                    : '（未录入 sudo 密码）'
                : ''}`}`,
        `  可读路径: ${host.allowedPaths.join('、')}`,
        `  可编辑路径: ${host.editablePaths.length === 0 ? '（未配置；写入仅限下面的临时目录）' : host.editablePaths.join('、')}`,
        `  临时目录: ${host.tempDir === null
            ? '未启用（tempDir 已关闭）'
            : `${host.tempDir}（默认授予读写；过程文件一律放这里，任务结束用 rm -f 清理，不要写进服务目录）`}`,
        `  禁止路径: ${host.deniedPaths.join('、')}`,
        ...(host.defaultCwd === null ? [] : [`  默认目录: ${host.defaultCwd}`]),
        ...(host.tags.length === 0 ? [] : [`  标签: ${host.tags.join('、')}`]),
        ...(host.note === null ? [] : [`  备注: ${host.note}`]),
    ];
    if (host.services.length === 0) {
        lines.push('  服务目录: 未声明');
    }
    else {
        lines.push('  服务目录:');
        for (const service of host.services) {
            const extra = [
                service.description ?? null,
                service.startCommand === undefined ? null : `启动: ${service.startCommand}`,
                service.logPath === undefined ? null : `日志: ${service.logPath}`,
                service.port === undefined ? null : `端口: ${service.port}`,
            ].filter((entry) => entry !== null);
            lines.push(`    - ${service.name} -> ${service.directory}${extra.length === 0 ? '' : ` — ${extra.join('；')}`}`);
        }
    }
    return lines.join('\n');
}
const SERVICE_VIEW_SCHEMA = {
    ...SERVICE_SCHEMA,
    properties: {
        server: { type: 'string', required: true, description: 'Host alias.' },
        ...SERVICE_SCHEMA.properties,
    },
};
/** Register the five inventory/connectivity tools on the plugin context. */
export function registerHostTools(ctx, deps) {
    ctx.tools.register(defineTool({
        name: 'ssh_host_add',
        description: 'Add one Linux server to the local SSH inventory. Use it when the user wants a new server available for later commands. ' +
            'The tool accepts no password and no private-key material: after adding, the user must provision the credential locally with the bundled CLI or environment variables. ' +
            'Adding a host does not contact the server; call ssh_test afterwards. allowedPaths controls reads; editablePaths separately controls writes/uploads and defaults to empty, in which case only the shared temp directory (tempDir, /tmp by default) is writable. ' +
            'Declare services with name + directory so later Agent turns know where each service lives.',
        parameters: {
            alias: { type: 'string', required: true, description: 'Unique short name used by every other ssh_* tool, e.g. web-1.' },
            host: { type: 'string', required: true, description: 'IP address or DNS name of the server.' },
            port: { type: 'integer', description: 'SSH port; defaults to 22.' },
            username: { type: 'string', required: true, description: 'Login user, e.g. deploy or root.' },
            authType: { type: 'string', required: true, enum: ['password', 'key'], description: 'password or key. The secret itself is never passed to this tool.' },
            privateKeyPath: { type: 'string', description: 'Local private-key path; required when authType=key. The key is read, never copied or printed.' },
            defaultCwd: { type: 'string', description: 'Default remote working directory, e.g. ~/app. Defaults to the login home.' },
            allowedPaths: { type: 'array', items: { type: 'string' }, description: 'Remote roots this host may READ, e.g. ["~/app","/tmp"]. Defaults to ["~"].' },
            editablePaths: { type: 'array', items: { type: 'string' }, description: 'Remote roots this host may EDIT/upload to. Empty (default) leaves only the shared temp directory writable. Should normally be a narrow service directory such as ["~/app"].' },
            services: { type: 'array', items: SERVICE_SCHEMA, description: 'Service directory notes: name, directory, optional description/startCommand/logPath/port.' },
            hostKeyFingerprint: { type: 'string', description: 'Optional pre-trusted OpenSSH SHA256 host-key fingerprint (SHA256:...). When supplied, the first connection is already strict instead of TOFU.' },
            tags: { type: 'array', items: { type: 'string' }, description: 'Optional labels such as prod or web.' },
            note: { type: 'string', description: 'Optional human note.' },
            fingerprintPolicy: { type: 'string', enum: ['strict', 'accept-new'], description: 'strict requires a stored fingerprint; accept-new trusts and records the first key. Defaults to strict.' },
            readOnly: { type: 'boolean', description: 'When true, commands and remote writes are refused; reads and downloads still work.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    host: { ...HOST_VIEW_SCHEMA, required: true },
                    credentialStatus: { type: 'string', required: true, enum: ['available', 'missing', 'unavailable'] },
                    nextStep: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                },
            },
            render: (_args, value) => {
                const lines = [`已添加 SSH 主机：`, renderHost(value.host)];
                if (value.nextStep !== null)
                    lines.push(`下一步：${value.nextStep}`);
                return [{ type: 'text', text: lines.join('\n') }];
            },
        },
        async execute(args, exec) {
            const record = await deps.store.add({
                alias: args.alias,
                host: args.host,
                ...(args.port === undefined ? {} : { port: args.port }),
                username: args.username,
                authType: args.authType,
                ...(args.privateKeyPath === undefined ? {} : { privateKeyPath: args.privateKeyPath }),
                ...(args.defaultCwd === undefined ? {} : { defaultCwd: args.defaultCwd }),
                ...(args.allowedPaths === undefined ? {} : { allowedPaths: args.allowedPaths }),
                ...(args.editablePaths === undefined ? {} : { editablePaths: args.editablePaths }),
                ...(args.services === undefined ? {} : { services: args.services }),
                ...(args.hostKeyFingerprint === undefined ? {} : { hostKeyFingerprint: args.hostKeyFingerprint }),
                ...(args.tags === undefined ? {} : { tags: args.tags }),
                ...(args.note === undefined ? {} : { note: args.note }),
                ...(args.fingerprintPolicy === undefined ? {} : { fingerprintPolicy: args.fingerprintPolicy }),
                readOnly: args.readOnly === true,
            });
            const status = await credentialStatusOf(record, deps);
            const hint = operationalHints(record, status, configuredTempDir(deps.config));
            await deps.audit.append({ action: 'host_add', server: record.alias, hostId: record.id, user: record.username, ok: true });
            deps.debug(`host added ${record.alias} (${record.id}) credentials=${status}`);
            return { host: await viewOf(record, deps), credentialStatus: status, nextStep: hint };
        },
        presentCall: (args) => ({
            card: 'generic',
            title: `Add SSH host ${args.alias}`,
            kind: 'other',
            rawInput: { host: args.host, port: args.port ?? 22, username: args.username, authType: args.authType },
        }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_host_list',
        description: 'List every configured SSH server with redacted connection metadata, credential availability, fingerprint state, read-only flag, read/edit path policy, the shared temp directory, and declared service directories. ' +
            'Call it before running a command when the server name is unknown; use ssh_services for a focused service list. Passwords, private keys, and key-file contents are never included. ' +
            'Each host shows its tempDir: that directory is readable and writable by default, so put process/scratch files there and remove them when done instead of writing them into service directories.',
        parameters: {},
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    hosts: { type: 'array', required: true, items: HOST_VIEW_SCHEMA },
                    count: { type: 'integer', required: true },
                    nextStep: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                },
            },
            render: (_args, value) => {
                if (value.count === 0) {
                    return [{ type: 'text', text: '尚未配置任何 SSH 服务器。请先用 ssh_host_add 添加主机，再由用户在本机录入凭据。' }];
                }
                const lines = [`已配置 ${value.count} 台 SSH 服务器：`, ''];
                for (const host of value.hosts)
                    lines.push(renderHost(host), '');
                if (value.nextStep !== null)
                    lines.push(value.nextStep);
                return [{ type: 'text', text: lines.join('\n').trimEnd() }];
            },
        },
        async execute() {
            const hosts = await deps.store.list();
            const views = [];
            for (const host of hosts)
                views.push(await viewOf(host, deps));
            const missing = views.filter((host) => host.credentialStatus !== 'available');
            const noEdit = views.filter((host) => host.editablePaths.length === 0);
            const noServices = views.filter((host) => host.services.length === 0);
            const notes = [];
            if (missing.length > 0) {
                notes.push(`${missing.map((host) => host.alias).join('、')} 缺少可用凭据；请由用户在本机运行 scripts/dsh-ssh.mjs 录入，或配置环境变量。`);
            }
            if (noEdit.length > 0) {
                const scratch = configuredTempDir(deps.config);
                notes.push(scratch === null
                    ? `${noEdit.map((host) => host.alias).join('、')} 未配置 editablePaths，Agent 只能读取/下载；如需编辑请由用户编辑 hosts.json。`
                    : `${noEdit.map((host) => host.alias).join('、')} 未配置 editablePaths，Agent 只能读取/下载，写入仅限临时目录 ${scratch}；如需编辑服务文件请由用户编辑 hosts.json。`);
            }
            if (noServices.length > 0) {
                notes.push(`${noServices.map((host) => host.alias).join('、')} 尚未声明 services；请用 ssh_host_update 补充服务名与目录。`);
            }
            return {
                hosts: views,
                count: views.length,
                nextStep: notes.length === 0 ? null : notes.join(' '),
            };
        },
        presentCall: () => ({ card: 'generic', title: 'List SSH hosts', kind: 'other' }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_services',
        description: 'List the declared service directories of one server or every server. Call it before inspecting, building, restarting, or editing a service so you know which directory belongs to which service. ' +
            'Each entry carries server alias, service name, directory, and optional description, startCommand, logPath, and port. It reads local inventory only and never contacts the server.',
        parameters: {
            server: { type: 'string', description: 'Host id or alias. Omit to list services for every host.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    services: { type: 'array', required: true, items: SERVICE_VIEW_SCHEMA },
                    count: { type: 'integer', required: true },
                },
            },
            render: (_args, value) => {
                if (value.count === 0) {
                    return [{ type: 'text', text: '尚未声明任何服务目录。请用 ssh_host_update 的 services 参数补充每个服务的 name 与 directory。' }];
                }
                const lines = [`已声明 ${value.count} 个服务目录：`];
                let current = '';
                for (const service of value.services) {
                    if (service.server !== current) {
                        current = service.server;
                        lines.push(`${current}:`);
                    }
                    const extra = [
                        service.description ?? null,
                        service.startCommand === undefined ? null : `启动: ${service.startCommand}`,
                        service.logPath === undefined ? null : `日志: ${service.logPath}`,
                        service.port === undefined ? null : `端口: ${service.port}`,
                    ].filter((entry) => entry !== null);
                    lines.push(`  - ${service.name} -> ${service.directory}${extra.length === 0 ? '' : ` — ${extra.join('；')}`}`);
                }
                return [{ type: 'text', text: lines.join('\n') }];
            },
        },
        async execute(args) {
            const hosts = args.server === undefined ? await deps.store.list() : [await deps.store.find(args.server)];
            const services = [];
            for (const host of hosts) {
                for (const service of host.services)
                    services.push({ server: host.alias, ...service });
            }
            return { services, count: services.length };
        },
        presentCall: (args) => ({ card: 'generic', title: args.server === undefined ? 'List SSH services' : `List services on ${args.server}`, kind: 'other' }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_host_update',
        description: 'Change safe metadata on one existing server: alias, default directory, tags, note, service directory notes, auth type, or tighten security (turn read-only on, tighten the host-key policy). ' +
            'Security-critical fields are locked after creation and rejected here: host address, port, login user, allowed paths, editable paths, key path, widening the fingerprint policy, and turning read-only off. ' +
            'To change a locked field the user must remove and re-add the host (which deletes its credentials) or edit hosts.json directly. It never accepts passwords or private-key material.',
        parameters: {
            server: { type: 'string', required: true, description: 'Host id or alias.' },
            alias: { type: 'string', description: 'New unique alias.' },
            host: { type: 'string', description: 'Locked identity field; only the current value is accepted.' },
            port: { type: 'integer', description: 'Locked identity field; only the current value is accepted.' },
            username: { type: 'string', description: 'Locked identity field; only the current value is accepted.' },
            authType: { type: 'string', enum: ['password', 'key'], description: 'Switch the authentication method; the user must then provision the matching credential.' },
            privateKeyPath: { type: 'string', description: 'Locked; only the current key path is accepted.' },
            defaultCwd: { type: 'string', description: 'New default remote directory; an empty string clears it.' },
            allowedPaths: { type: 'array', items: { type: 'string' }, description: 'Locked policy; only the current array is accepted.' },
            editablePaths: { type: 'array', items: { type: 'string' }, description: 'Locked edit policy; only the current array is accepted. Change it in hosts.json.' },
            services: { type: 'array', items: SERVICE_SCHEMA, description: 'Replacement service directory notes. Safe to edit; use it to record where each service lives.' },
            tags: { type: 'array', items: { type: 'string' }, description: 'Replacement tags.' },
            note: { type: 'string', description: 'New note; an empty string clears it.' },
            fingerprintPolicy: { type: 'string', enum: ['strict', 'accept-new'], description: 'Only tightening to strict is allowed; widening to accept-new is rejected.' },
            readOnly: { type: 'boolean', description: 'May turn read-only on; turning it off is rejected.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    host: { ...HOST_VIEW_SCHEMA, required: true },
                    credentialStatus: { type: 'string', required: true, enum: ['available', 'missing', 'unavailable'] },
                    nextStep: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                },
            },
            render: (_args, value) => {
                const lines = ['已更新 SSH 主机：', renderHost(value.host)];
                if (value.nextStep !== null)
                    lines.push(`下一步：${value.nextStep}`);
                return [{ type: 'text', text: lines.join('\n') }];
            },
        },
        async execute(args) {
            const record = await deps.store.update(args.server, {
                ...(args.alias === undefined ? {} : { alias: args.alias }),
                ...(args.host === undefined ? {} : { host: args.host }),
                ...(args.port === undefined ? {} : { port: args.port }),
                ...(args.username === undefined ? {} : { username: args.username }),
                ...(args.authType === undefined ? {} : { authType: args.authType }),
                ...(args.privateKeyPath === undefined ? {} : { privateKeyPath: args.privateKeyPath }),
                ...(args.defaultCwd === undefined ? {} : { defaultCwd: args.defaultCwd.length === 0 ? null : args.defaultCwd }),
                ...(args.allowedPaths === undefined ? {} : { allowedPaths: args.allowedPaths }),
                ...(args.editablePaths === undefined ? {} : { editablePaths: args.editablePaths }),
                ...(args.services === undefined ? {} : { services: args.services }),
                ...(args.tags === undefined ? {} : { tags: args.tags }),
                ...(args.note === undefined ? {} : { note: args.note.length === 0 ? null : args.note }),
                ...(args.fingerprintPolicy === undefined ? {} : { fingerprintPolicy: args.fingerprintPolicy }),
                ...(args.readOnly === undefined ? {} : { readOnly: args.readOnly }),
            });
            const status = await credentialStatusOf(record, deps);
            await deps.audit.append({ action: 'host_update', server: record.alias, hostId: record.id, user: record.username, ok: true });
            return { host: await viewOf(record, deps), credentialStatus: status, nextStep: operationalHints(record, status, configuredTempDir(deps.config)) };
        },
        presentCall: (args) => ({ card: 'generic', title: `Update SSH host ${args.server}`, kind: 'other' }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_host_remove',
        description: 'Permanently remove one server and its locally stored credentials. Use only when the user asks to forget a server. ' +
            'The connection is closed lazily; other servers are unaffected.',
        parameters: {
            server: { type: 'string', required: true, description: 'Host id or alias to remove.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    removed: { type: 'boolean', required: true },
                    alias: { type: 'string', required: true },
                    id: { type: 'string', required: true },
                    credentialsDeleted: { type: 'integer', required: true },
                    nextStep: { type: 'string', required: true },
                },
            },
            render: (_args, value) => [
                {
                    type: 'text',
                    text: `已删除 SSH 主机 ${value.alias}（${value.id}），同时清除 ${value.credentialsDeleted} 条本地凭据。${value.nextStep}`,
                },
            ],
        },
        async execute(args) {
            const removed = await deps.store.remove(args.server);
            const credentialsDeleted = await deps.secrets.deleteHost(removed.id);
            await deps.audit.append({ action: 'host_remove', server: removed.alias, hostId: removed.id, user: removed.username, ok: true });
            return {
                removed: true,
                alias: removed.alias,
                id: removed.id,
                credentialsDeleted,
                nextStep: '该服务器已不可再执行命令；如仍需要请重新添加。',
            };
        },
        presentCall: (args) => ({ card: 'generic', title: `Remove SSH host ${args.server}`, kind: 'delete' }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_test',
        description: 'Check DNS, TCP, SSH handshake, authentication, host-key trust, and the remote home directory for one server without running a command. ' +
            'Use it after adding a host, after a connection failure, or when a fingerprint warning appears. A first connection under accept-new records the fingerprint and reports it.',
        parameters: {
            server: { type: 'string', required: true, description: 'Host id or alias.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    server: { type: 'string', required: true },
                    reachable: { type: 'boolean', required: true },
                    authOk: { type: 'boolean', required: true },
                    hostKeyFingerprint: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                    hostKeyStatus: { type: 'string', required: true, enum: ['matched', 'learned', 'changed', 'unknown', 'not-checked'] },
                    banner: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                    homeDir: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                    durationMs: { type: 'integer', required: true },
                    error: {
                        oneOf: [
                            {
                                type: 'object',
                                additionalProperties: false,
                                properties: {
                                    code: { type: 'string', required: true },
                                    message: { type: 'string', required: true },
                                    hint: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
                                },
                            },
                            { type: 'null' },
                        ],
                        required: true,
                    },
                },
            },
            render: (_args, value) => {
                const lines = [
                    `SSH 自检：${value.server}`,
                    `  可达: ${value.reachable ? '是' : '否'}  认证: ${value.authOk ? '成功' : '失败'}  主机密钥: ${value.hostKeyStatus}`,
                    `  指纹: ${value.hostKeyFingerprint ?? '未取得'}`,
                    `  home: ${value.homeDir ?? '未知'}  耗时: ${value.durationMs} ms`,
                ];
                if (value.banner !== null)
                    lines.push(`  banner: ${value.banner.trim()}`);
                if (value.error !== null)
                    lines.push(`  错误: ${value.error.message} [${value.error.code}]`, ...(value.error.hint === null ? [] : [`  提示: ${value.error.hint}`]));
                return [{ type: 'text', text: lines.join('\n') }];
            },
        },
        async execute(args) {
            const host = await deps.store.find(args.server);
            const result = await deps.manager.test(host);
            await deps.audit.append({
                action: 'test',
                server: host.alias,
                hostId: host.id,
                user: host.username,
                ok: result.error === null,
                ...(result.error === null ? {} : { code: result.error.code }),
                durationMs: result.durationMs,
            });
            return result;
        },
        presentCall: (args) => ({ card: 'generic', title: `Test SSH host ${args.server}`, kind: 'other' }),
    }));
}
