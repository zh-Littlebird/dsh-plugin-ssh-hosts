/**
 * One redaction boundary for everything that leaves the plugin: tool results,
 * errors, audit lines, and debug logs.
 */
const knownSecrets = new Set();
/** Remember a secret so it can never appear verbatim in any output. */
export function registerSecret(value) {
    if (typeof value !== 'string' || value.length < 4)
        return;
    knownSecrets.add(value);
}
/** Drop a secret from the in-memory registry. */
export function forgetSecret(value) {
    if (typeof value === 'string')
        knownSecrets.delete(value);
}
const PATTERNS = [
    [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '-----BEGIN PRIVATE KEY-----***REDACTED***-----END PRIVATE KEY-----'],
    [/\b(password|passwd|passphrase)\s*[=:]\s*("[^"]*"|'[^']*'|\S+)/gi, '$1=***REDACTED***'],
    [/\bAuthorization\s*:\s*[^\r\n]+/gi, 'Authorization: ***REDACTED***'],
    [/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, 'Bearer ***REDACTED***'],
    [/([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi, '$1***:***@'],
];
/**
 * Redact registered secret values plus well-known credential shapes.
 * Registered values are replaced first, longest first, so overlapping
 * secrets cannot leave a fragment behind.
 */
export function redact(text) {
    if (text.length === 0)
        return text;
    let output = text;
    const ordered = [...knownSecrets].sort((a, b) => b.length - a.length);
    for (const secret of ordered) {
        if (secret.length === 0)
            continue;
        output = output.split(secret).join('***REDACTED***');
    }
    for (const [pattern, replacement] of PATTERNS) {
        output = output.replace(pattern, replacement);
    }
    return output;
}
/** Redact an unknown thrown value into one readable line without a stack. */
export function redactError(error) {
    if (error instanceof Error)
        return redact(error.message);
    return redact(String(error));
}
/** A stderr logger that is silent unless enabled and redacts every line. */
export function createDebugLogger(enabled) {
    return (message) => {
        if (!enabled)
            return;
        process.stderr.write(`[ssh-hosts] ${redact(message)}\n`);
    };
}
