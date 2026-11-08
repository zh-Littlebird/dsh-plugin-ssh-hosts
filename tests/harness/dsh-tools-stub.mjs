// Test-only stand-in for the harness's defineTool: the real function only
// validates and returns the same definition object. The live profile proves
// the real import resolves via --dump-config-schema.
export function defineTool(options) {
  return options
}
