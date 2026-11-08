/** Remote file read/write and local↔remote transfer tools. */
import { defineTool } from '@deepseek-ai/dsh-tools';
import { localRoots, resolveLocalPath } from '../local.js';
import { formatBytes } from '../output.js';
/** Register the four SFTP tools. */
export function registerFileTools(ctx, deps) {
    ctx.tools.register(defineTool({
        name: 'ssh_read_file',
        description: 'Read one remote text file over SFTP and return its content plus byte counts and truncation state. ' +
            'Use it when the model needs file content (configs, logs, source, or a file it just wrote to the temp directory). The path must be inside the server allowedPaths and outside deniedPaths, including after symlink resolution. ' +
            'Binary files are refused; use ssh_download for those. Reading is capped by maxTransferBytes; if maxBytes is lower, only the beginning is returned and truncated=true.',
        parameters: {
            server: { type: 'string', required: true, description: 'Host id or alias.' },
            path: { type: 'string', required: true, description: 'Remote file path; absolute, ~/…, or relative to the server defaultCwd.' },
            maxBytes: { type: 'integer', description: 'Maximum bytes to return; bounded by maxTransferBytes.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    server: { type: 'string', required: true },
                    path: { type: 'string', required: true },
                    content: { type: 'string', required: true },
                    bytes: { type: 'integer', required: true },
                    originalBytes: { type: 'integer', required: true },
                    truncated: { type: 'boolean', required: true },
                },
            },
            render: (_args, value) => {
                const header = `SSH ${value.server} · ${value.path} · ${formatBytes(value.bytes)}${value.truncated ? `（文件共 ${formatBytes(value.originalBytes)}，仅返回开头）` : ''}`;
                return [{ type: 'text', text: `${header}\n--- content ---\n${value.content}` }];
            },
        },
        async execute(args) {
            const host = await deps.store.find(args.server);
            const maxBytes = args.maxBytes ?? deps.config.maxTransferBytes;
            const result = await deps.manager.readFile(host, args.path, maxBytes);
            await deps.audit.append({
                action: 'read',
                server: host.alias,
                hostId: host.id,
                user: host.username,
                path: result.path,
                ok: true,
            });
            return {
                server: host.alias,
                path: result.path,
                content: result.content,
                bytes: result.bytes,
                originalBytes: result.originalBytes,
                truncated: result.truncated,
            };
        },
        presentCall: (args) => ({ card: 'generic', title: `Read ${args.path}`, kind: 'read', rawInput: { server: args.server } }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_write_file',
        description: 'Create or replace one remote text file over SFTP. Use it for deliberate edits on a configured server. ' +
            'Writes are refused on read-only servers, outside editablePaths, and inside deniedPaths, including through symlinked parents. ' +
            'Scratch and process files belong in the host temp directory (tempDir, /tmp by default), which stays writable by default: write there and remove the file when you are done instead of leaving temp files in service directories. ' +
            'Parent directories are created only with createDirs=true; overwrite defaults to true, pass false to fail when the file exists. Content is capped by maxTransferBytes.',
        parameters: {
            server: { type: 'string', required: true, description: 'Host id or alias.' },
            path: { type: 'string', required: true, description: 'Remote file path; absolute, ~/…, or relative to the server defaultCwd.' },
            content: { type: 'string', required: true, description: 'Full UTF-8 text to write.' },
            createDirs: { type: 'boolean', description: 'Create missing parent directories. Defaults to false.' },
            overwrite: { type: 'boolean', description: 'Replace an existing file. Defaults to true; false makes an existing file an error.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    server: { type: 'string', required: true },
                    path: { type: 'string', required: true },
                    bytesWritten: { type: 'integer', required: true },
                    created: { type: 'boolean', required: true },
                    overwritten: { type: 'boolean', required: true },
                },
            },
            render: (_args, value) => [
                {
                    type: 'text',
                    text: `已写入 ${value.server}:${value.path}（${formatBytes(value.bytesWritten)}，${value.created ? '新建' : '覆盖'}）`,
                },
            ],
        },
        async execute(args) {
            const host = await deps.store.find(args.server);
            const result = await deps.manager.writeFile(host, args.path, args.content, {
                createDirs: args.createDirs === true,
                overwrite: args.overwrite !== false,
            });
            await deps.audit.append({
                action: 'write',
                server: host.alias,
                hostId: host.id,
                user: host.username,
                path: result.path,
                ok: true,
            });
            return { server: host.alias, ...result };
        },
        presentCall: (args) => ({ card: 'generic', title: `Write ${args.path}`, kind: 'edit', rawInput: { server: args.server, bytes: Buffer.byteLength(args.content, 'utf8') } }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_upload',
        description: 'Upload one local file to a configured server over SFTP. The local path must be inside the session workspace, localRoots, or the plugin transfers directory. ' +
            'The remote path must stay inside editablePaths (the host temp directory, tempDir, is editable by default); read-only servers are refused. Overwrite defaults to false, so replacing an existing remote file needs overwrite=true. ' +
            'For text content without a local file, prefer ssh_write_file.',
        parameters: {
            server: { type: 'string', required: true, description: 'Host id or alias.' },
            localPath: { type: 'string', required: true, description: 'Local file path inside the workspace/localRoots/transfers.' },
            remotePath: { type: 'string', required: true, description: 'Destination remote path; absolute, ~/…, or relative to defaultCwd.' },
            createDirs: { type: 'boolean', description: 'Create missing remote parent directories. Defaults to false.' },
            overwrite: { type: 'boolean', description: 'Replace an existing remote file. Defaults to false.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    server: { type: 'string', required: true },
                    localPath: { type: 'string', required: true },
                    remotePath: { type: 'string', required: true },
                    bytes: { type: 'integer', required: true },
                    overwritten: { type: 'boolean', required: true },
                },
            },
            render: (_args, value) => [
                {
                    type: 'text',
                    text: `已上传 ${value.localPath} → ${value.server}:${value.remotePath}（${formatBytes(value.bytes)}${value.overwritten ? '，已覆盖' : ''}）`,
                },
            ],
        },
        async execute(args, exec) {
            const host = await deps.store.find(args.server);
            const local = resolveLocalPath(args.localPath, localRoots(deps, exec), deps.config);
            const result = await deps.manager.upload(host, local, args.remotePath, {
                createDirs: args.createDirs === true,
                overwrite: args.overwrite === true,
            });
            await deps.audit.append({
                action: 'upload',
                server: host.alias,
                hostId: host.id,
                user: host.username,
                path: result.remotePath,
                ok: true,
            });
            return { server: host.alias, localPath: local, remotePath: result.remotePath, bytes: result.bytes, overwritten: result.overwritten };
        },
        presentCall: (args) => ({ card: 'generic', title: `Upload to ${args.server}`, kind: 'other', rawInput: { localPath: args.localPath, remotePath: args.remotePath } }),
    }));
    ctx.tools.register(defineTool({
        name: 'ssh_download',
        description: 'Download one remote file to the local workspace over SFTP. Use it for binary files or files too large for ssh_read_file. ' +
            'The remote path must stay inside allowedPaths (which includes the host temp directory); the local path must be inside the session workspace, localRoots, or the transfers directory. ' +
            'Overwrite defaults to false, so replacing an existing local file needs overwrite=true. The file is written through a temporary sibling.',
        parameters: {
            server: { type: 'string', required: true, description: 'Host id or alias.' },
            remotePath: { type: 'string', required: true, description: 'Remote source file path.' },
            localPath: { type: 'string', required: true, description: 'Local destination inside the workspace/localRoots/transfers.' },
            overwrite: { type: 'boolean', description: 'Replace an existing local file. Defaults to false.' },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    server: { type: 'string', required: true },
                    remotePath: { type: 'string', required: true },
                    localPath: { type: 'string', required: true },
                    bytes: { type: 'integer', required: true },
                    overwritten: { type: 'boolean', required: true },
                },
            },
            render: (_args, value) => [
                {
                    type: 'text',
                    text: `已下载 ${value.server}:${value.remotePath} → ${value.localPath}（${formatBytes(value.bytes)}${value.overwritten ? '，已覆盖' : ''}）`,
                },
            ],
        },
        async execute(args, exec) {
            const host = await deps.store.find(args.server);
            const local = resolveLocalPath(args.localPath, localRoots(deps, exec), deps.config);
            const result = await deps.manager.download(host, args.remotePath, local, {
                overwrite: args.overwrite === true,
            });
            await deps.audit.append({
                action: 'download',
                server: host.alias,
                hostId: host.id,
                user: host.username,
                path: result.remotePath,
                ok: true,
            });
            return { server: host.alias, remotePath: result.remotePath, localPath: local, bytes: result.bytes, overwritten: result.overwritten };
        },
        presentCall: (args) => ({ card: 'generic', title: `Download from ${args.server}`, kind: 'other', rawInput: { remotePath: args.remotePath, localPath: args.localPath } }),
    }));
}
