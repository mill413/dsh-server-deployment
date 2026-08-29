'use strict';

const http = require('http');

const host = process.env.HOST || '0.0.0.0';
const port = Number(process.env.PORT || 8080);
const counters = { models: 0, chat: 0, responses: 0 };

function json(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    'content-type': 'application/json',
    'content-length': body.length,
    'cache-control': 'no-store',
  });
  response.end(body);
}

function readJson(request, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) request.destroy(new Error('payload too large'));
      else chunks.push(chunk);
    });
    request.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (error) { reject(error); }
    });
    request.on('error', reject);
  });
}

const server = http.createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://mock').pathname;
  if (pathname === '/health') return json(response, 200, { ok: true });
  if (pathname === '/stats') return json(response, 200, { ok: true, counters });
  if (pathname === '/v1/models' && request.method === 'GET') {
    counters.models += 1;
    return json(response, 200, {
      object: 'list',
      data: [
        { id: 'mock-chat-model', object: 'model', owned_by: 'local-test' },
        { id: 'mock-vision-model', object: 'model', owned_by: 'local-test' },
      ],
    });
  }
  if (pathname === '/v1/chat/completions' && request.method === 'POST') {
    counters.chat += 1;
    let body;
    try { body = await readJson(request); } catch (error) { return json(response, 400, { error: { message: error.message } }); }
    const content = 'mock response for ' + String(body.model || 'unknown');
    if (body.stream === true) {
      response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
      response.write('data: ' + JSON.stringify({ id: 'mock-chat', object: 'chat.completion.chunk', choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }] }) + '\n\n');
      response.write('data: ' + JSON.stringify({ id: 'mock-chat', object: 'chat.completion.chunk', choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }) + '\n\n');
      response.end('data: [DONE]\n\n');
      return;
    }
    return json(response, 200, {
      id: 'mock-chat',
      object: 'chat.completion',
      model: body.model || 'mock-chat-model',
      choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 1, completion_tokens: 4, total_tokens: 5 },
    });
  }
  if (pathname === '/v1/responses' && request.method === 'POST') {
    counters.responses += 1;
    let body;
    try { body = await readJson(request); } catch (error) { return json(response, 400, { error: { message: error.message } }); }
    return json(response, 200, {
      id: 'mock-response',
      object: 'response',
      status: 'completed',
      model: body.model || 'mock-chat-model',
      output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'mock response' }] }],
      usage: { input_tokens: 1, output_tokens: 2, total_tokens: 3 },
    });
  }
  return json(response, 404, { error: { message: 'not found' } });
});

server.listen(port, host, () => console.log(`mock OpenAI service listening on ${host}:${port}`));
