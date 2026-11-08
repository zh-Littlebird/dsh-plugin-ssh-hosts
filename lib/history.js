/**
 * Audit history for humans: read `audit.log` and serve it to the Web panel.
 *
 * The audit log already records every SSH action (command, path, exit code,
 * duration, approval outcome) and never contains credential material. This
 * module only turns that append-only JSONL file into a read-only HTTP view so
 * the user can see what the agent did on the servers without opening a shell
 * or asking the model.
 *
 * An alias is a mutable label. Every entry written by this version carries the
 * stable `hostId`, so history resolves each row to the server's *current* alias
 * and the server filter lists the inventory once — renaming a host never adds
 * another "server" to the panel. Host-management records (`host_add`,
 * `host_update`, `host_remove`, credential edits) stay in `audit.log` for
 * compliance but are not command history, so they are not shown here.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { registerPrefixRoute, sendError, sendJson } from './web.js';
const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;
/** Host-inventory events are not commands and are excluded from this panel. */
const EXCLUDED_ACTIONS = new Set([
    'host_add',
    'host_update',
    'host_remove',
    'credential',
]);
/** URL prefix this plugin claims on the Harness web server. */
export const ROUTE_PREFIX = '/ssh-hosts-api';
function parseAuditText(text) {
    const entries = [];
    for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.length === 0)
            continue;
        try {
            const parsed = JSON.parse(trimmed);
            if (typeof parsed.time !== 'string')
                continue;
            if (typeof parsed.action !== 'string' || typeof parsed.server !== 'string')
                continue;
            entries.push(parsed);
        }
        catch {
            // A half-written trailing line is expected after a crash; skip it.
        }
    }
    return entries;
}
async function readAuditFile(path) {
    try {
        return parseAuditText(await readFile(path, 'utf8'));
    }
    catch {
        // No log yet, or it is unreadable: an empty history is not an error.
        return [];
    }
}
function clampLimit(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0)
        return DEFAULT_LIMIT;
    return Math.min(MAX_LIMIT, Math.floor(value));
}
function splitActions(value) {
    if (value === undefined)
        return [];
    return value
        .split(',')
        .map((part) => part.trim().toLowerCase())
        .filter((part) => part.length > 0);
}
function addressAliases(host) {
    const name = host.host.trim().toLowerCase();
    const aliases = new Set([name]);
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(name)) {
        const dashed = name.replace(/\./g, '-');
        aliases.add(dashed);
        aliases.add(`ssh-${dashed}`);
        aliases.add(`ssh-${name}`);
    }
    return [...aliases];
}
function indexHosts(hosts) {
    const byId = new Map();
    const byAlias = new Map();
    const byLowerAlias = new Map();
    const legacy = new Map();
    const ambiguous = new Set();
    for (const host of hosts) {
        byId.set(host.id, host);
        byAlias.set(host.alias, host);
        byLowerAlias.set(host.alias.toLowerCase(), host);
        for (const alias of addressAliases(host)) {
            const existing = legacy.get(alias);
            if (existing !== undefined && existing !== host.id)
                ambiguous.add(alias);
            else
                legacy.set(alias, host.id);
        }
    }
    for (const alias of ambiguous)
        legacy.delete(alias);
    return { byId, byAlias, byLowerAlias, legacy };
}
function legacyHostFor(server, index) {
    const id = index.legacy.get(server.trim().toLowerCase());
    return id === undefined ? undefined : index.byId.get(id);
}
/** Stable filter key for one host address (IP or DNS name). */
function ipKey(address) {
    return `ip:${address.trim().toLowerCase()}`;
}
/**
 * Resolve one entry to the address of its host, when the host still exists.
 * The historical alias is kept on `server` for tooltips, but grouping and
 * filtering use the address.
 */
function resolveEntry(entry, index) {
    const host = (entry.hostId === undefined ? undefined : index.byId.get(entry.hostId)) ??
        index.byAlias.get(entry.server) ??
        legacyHostFor(entry.server, index);
    if (host === undefined)
        return entry;
    return { ...entry, server: host.alias, serverIp: host.host, serverId: ipKey(host.host) };
}
/**
 * Read the audit trail, newest first. `audit.log.1` is older than `audit.log`
 * because rotation renames the current file aside. `hosts` is the current
 * inventory; it supplies the server rows (grouped by host address) and the
 * address each entry belongs to.
 */
export async function readHistory(dataDir, query = {}, auditEnabled = true, hosts = []) {
    const [rotated, current] = await Promise.all([
        readAuditFile(join(dataDir, 'audit.log.1')),
        readAuditFile(join(dataDir, 'audit.log')),
    ]);
    const index = indexHosts(hosts);
    const raw = rotated.concat(current).filter((entry) => !EXCLUDED_ACTIONS.has(entry.action.toLowerCase()));
    // Newer entries carry both the stable id and the alias used at the time, so
    // a query with an *old* alias still finds the same address.
    const aliasToHostId = new Map();
    for (const entry of raw) {
        if (entry.hostId !== undefined && entry.server.length > 0)
            aliasToHostId.set(entry.server, entry.hostId);
    }
    const all = raw.map((entry) => resolveEntry(entry, index));
    const groups = new Map();
    for (const host of hosts) {
        const address = host.host.trim();
        const id = ipKey(address);
        let group = groups.get(id);
        if (group === undefined) {
            group = { id, ip: address, count: 0, aliases: [] };
            groups.set(id, group);
        }
        if (!group.aliases.includes(host.alias))
            group.aliases.push(host.alias);
    }
    for (const entry of all) {
        if (entry.serverId === undefined)
            continue;
        const group = groups.get(entry.serverId);
        if (group !== undefined)
            group.count += 1;
    }
    const servers = [...groups.values()].sort((left, right) => left.ip.localeCompare(right.ip));
    const actions = splitActions(query.action);
    const rawServer = query.server?.trim();
    const matchedGroup = rawServer === undefined || rawServer.length === 0
        ? undefined
        : groups.get(rawServer) ??
            groups.get(ipKey(rawServer)) ??
            (() => {
                const host = index.byId.get(rawServer) ??
                    index.byAlias.get(rawServer) ??
                    index.byLowerAlias.get(rawServer.toLowerCase()) ??
                    legacyHostFor(rawServer, index) ??
                    (aliasToHostId.has(rawServer) ? index.byId.get(aliasToHostId.get(rawServer)) : undefined);
                return host === undefined ? undefined : groups.get(ipKey(host.host));
            })();
    const search = query.search?.trim().toLowerCase();
    const matched = all.filter((entry) => {
        if (rawServer !== undefined && rawServer.length > 0) {
            if (matchedGroup !== undefined) {
                if (entry.serverId !== matchedGroup.id)
                    return false;
            }
            else {
                const label = entry.serverIp ?? entry.server;
                if (label.toLowerCase() !== rawServer.toLowerCase())
                    return false;
            }
        }
        if (actions.length > 0 && !actions.includes(entry.action.toLowerCase()))
            return false;
        if (query.failedOnly === true && entry.ok !== false)
            return false;
        if (search !== undefined && search.length > 0) {
            const haystack = `${entry.command ?? ''}\n${entry.path ?? ''}`.toLowerCase();
            if (!haystack.includes(search))
                return false;
        }
        return true;
    });
    const limit = clampLimit(query.limit);
    return {
        entries: matched.slice(-limit).reverse(),
        total: all.length,
        matched: matched.length,
        returned: Math.min(limit, matched.length),
        auditEnabled,
        dataDir,
        generatedAt: new Date().toISOString(),
        servers,
    };
}
function numberParam(value) {
    if (value === null || value.length === 0)
        return undefined;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
}
/**
 * Register the read-only history endpoint the Web panel polls. A composition
 * without a web server (headless profiles) simply skips it.
 */
export function registerHistoryRoute(ctx, options) {
    const handler = async (req, res) => {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
            sendJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: '该端点只接受 GET', hint: `${ROUTE_PREFIX}/history` } });
            return;
        }
        const url = new URL(req.url ?? ROUTE_PREFIX, 'http://127.0.0.1');
        if (url.pathname !== `${ROUTE_PREFIX}/history`) {
            sendJson(res, 404, { error: { code: 'NOT_FOUND', message: '未知端点', hint: `可用端点：${ROUTE_PREFIX}/history` } });
            return;
        }
        try {
            let hosts = [];
            if (options.hosts !== undefined) {
                try {
                    hosts = await options.hosts();
                }
                catch {
                    // The inventory is a nicety here; history still works without it.
                    hosts = [];
                }
            }
            const page = await readHistory(options.dataDir, {
                limit: numberParam(url.searchParams.get('limit')),
                server: url.searchParams.get('server') ?? undefined,
                action: url.searchParams.get('action') ?? undefined,
                failedOnly: url.searchParams.get('failed') === '1',
                search: url.searchParams.get('q') ?? undefined,
            }, options.auditEnabled, hosts);
            sendJson(res, 200, page);
        }
        catch (error) {
            options.debug(`history request failed: ${error instanceof Error ? error.message : String(error)}`);
            sendError(res, 500, error);
        }
    };
    registerPrefixRoute(ctx, {
        dataDir: options.dataDir,
        path: ROUTE_PREFIX,
        name: 'history',
        statusFile: 'history-route.json',
        debug: options.debug,
        handler,
    });
}
