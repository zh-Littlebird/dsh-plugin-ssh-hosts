// Minimal OpenAI-compatible mock used only for end-to-end verification of the
// dev profile. First request: ask for ssh_exec. After the tool result: report it.
import http from 'node:http'

const port = Number(process.env.MOCK_LLM_PORT ?? 33333)
const toolName = process.env.MOCK_TOOL_NAME ?? 'ssh_exec'
const toolArgs = process.env.MOCK_TOOL_ARGS ?? JSON.stringify({ server: 'dev-1', command: 'uname -a && whoami' })

function textOf(content) {
  if (typeof content === 'string') return content
  if (Array.isArray(content)) return content.map((part) => (typeof part === 'string' ? part : part?.text ?? '')).join('\n')
  return JSON.stringify(content)
}

function sse(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`)
}

function completionChunk(delta, finishReason = null) {
  return {
    id: 'chatcmpl-mock',
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model: 'mock-model',
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  }
}

const server = http.createServer(async (req, res) => {
  if (!req.url?.endsWith('/chat/completions')) {
    res.writeHead(404).end('not found')
    return
  }
  let body = ''
  for await (const chunk of req) body += chunk
  const request = JSON.parse(body || '{}')
  const messages = Array.isArray(request.messages) ? request.messages : []
  const toolMessage = [...messages].reverse().find((message) => message.role === 'tool')

  res.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
  })

  if (toolMessage === undefined) {
    sse(res, completionChunk({ role: 'assistant', tool_calls: [
      { index: 0, id: 'call_mock_1', type: 'function', function: { name: toolName, arguments: '' } },
    ] }))
    sse(res, completionChunk({ tool_calls: [
      { index: 0, function: { arguments: toolArgs } },
    ] }))
    sse(res, completionChunk({}, 'tool_calls'))
    sse(res, {
      id: 'chatcmpl-mock',
      object: 'chat.completion.chunk',
      created: Math.floor(Date.now() / 1000),
      model: 'mock-model',
      choices: [],
      usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
    })
    res.write('data: [DONE]\n\n')
    res.end()
    return
  }

  const text = `E2E_TOOL_RESULT\n${textOf(toolMessage.content)}`
  sse(res, completionChunk({ role: 'assistant', content: '' }))
  sse(res, completionChunk({ content: text }))
  sse(res, completionChunk({}, 'stop'))
  res.write('data: [DONE]\n\n')
  res.end()
})

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`mock-llm listening on 127.0.0.1:${port}\n`)
})
