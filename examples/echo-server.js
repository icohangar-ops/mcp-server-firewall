#!/usr/bin/env node
// A tiny hand-rolled MCP stdio server (JSON-RPC 2.0, newline-delimited)
// used by the demo and the integration tests. Zero dependencies.
//
// Tools:
//   read_file   - reads a file from disk (the firewall scopes where)
//   echo        - returns the text it was given
//   print_env   - lists the environment variable NAMES visible to this
//                 process (demonstrates the firewall's env brokering)
//   delete_file - deletes a file. Deliberately dangerous, and deliberately
//                 NOT in the demo/test policy allowlists, so the firewall
//                 denies it before it ever reaches this server.

import fs from 'node:fs';
import readline from 'node:readline';

const TOOLS = [
  {
    name: 'read_file',
    description: 'Read a file from disk and return its contents.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
  {
    name: 'echo',
    description: 'Echo back the provided text.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string' } },
      required: ['text'],
    },
  },
  {
    name: 'print_env',
    description: 'Return the names of the environment variables visible to this server.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'delete_file',
    description: 'Delete a file from disk.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
];

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}
function result(id, res) {
  send({ jsonrpc: '2.0', id, result: res });
}
function error(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}
function textResult(id, text, isError = false) {
  result(id, { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) });
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  const { id, method, params } = msg;

  if (method === 'initialize') {
    result(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'echo-server', version: '1.0.0' },
    });
    return;
  }
  if (method === 'tools/list') {
    result(id, { tools: TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const name = params?.name;
    const a = params?.arguments ?? {};
    try {
      if (name === 'read_file') {
        textResult(id, fs.readFileSync(a.path, 'utf8'));
      } else if (name === 'echo') {
        textResult(id, String(a.text ?? ''));
      } else if (name === 'print_env') {
        textResult(id, JSON.stringify(Object.keys(process.env).sort()));
      } else if (name === 'delete_file') {
        fs.unlinkSync(a.path);
        textResult(id, `deleted ${a.path}`);
      } else {
        error(id, -32602, `unknown tool: ${name}`);
      }
    } catch (e) {
      textResult(id, `error: ${e.message}`, true);
    }
    return;
  }
  // Notifications (no id) need no response; unknown methods get an error.
  if (id !== undefined && id !== null) {
    error(id, -32601, `method not found: ${method}`);
  }
});
