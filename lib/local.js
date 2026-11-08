/** Local-side path confinement for upload and download. */
import { resolve } from 'node:path';
import { isPathInside } from './fs-util.js';
import { SshHostsError } from './types.js';
/** Roots a transfer may read from or write to: session workspace, config, transfers. */
export function localRoots(deps, exec) {
    const roots = [];
    const sessionCwd = exec.agent?.session?.header?.cwd;
    if (typeof sessionCwd === 'string' && sessionCwd.length > 0)
        roots.push(resolve(sessionCwd));
    for (const root of deps.config.localRoots)
        roots.push(resolve(root));
    roots.push(resolve(deps.dataDir, 'transfers'));
    return [...new Set(roots)];
}
/** Resolve a model-supplied local path and require it to stay inside a root. */
export function resolveLocalPath(input, roots, config) {
    if (input.trim().length === 0)
        throw new SshHostsError('INVALID_PATH', '本地路径不能为空', '请提供本地文件路径');
    const candidates = roots.map((root) => resolve(root, input));
    for (const candidate of candidates) {
        if (roots.some((root) => isPathInside(root, candidate)))
            return candidate;
    }
    throw new SshHostsError('LOCAL_PATH_DENIED', `本地路径越界：${input}`, `只允许会话工作区、localRoots 和 ${resolve(config.dataDir, 'transfers')}`);
}
