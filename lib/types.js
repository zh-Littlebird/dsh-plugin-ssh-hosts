/** Shared domain types and the plugin's structured error. */
/** An error that carries a stable machine code and an actionable hint. */
export class SshHostsError extends Error {
    code;
    hint;
    /** Host-key fingerprint observed at failure time, when one was seen. */
    fingerprint;
    constructor(code, message, hint, cause, fingerprint) {
        super(`${message} [${code}]`, cause === undefined ? undefined : { cause });
        this.name = 'SshHostsError';
        this.code = code;
        this.hint = hint ?? null;
        this.fingerprint = fingerprint ?? null;
    }
}
/** Render one error as a single model-facing line, keeping the hint. */
export function describeError(error) {
    if (error instanceof SshHostsError) {
        return error.hint ? `${error.message}（${error.hint}）` : error.message;
    }
    if (error instanceof Error)
        return error.message;
    return String(error);
}
