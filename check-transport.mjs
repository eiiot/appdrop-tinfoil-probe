// Run only against the CLI's local attestation-verifying proxy.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createRequire } from 'node:module';
const require = createRequire(new URL('./app/package.json', import.meta.url));
const WebSocket = require('ws');
const origin = new URL(process.argv[2] || 'http://127.0.0.1:63321');
assert.equal(origin.protocol, 'http:');
assert.equal(origin.hostname, '127.0.0.1');
const health = await fetch(new URL('/health', origin), { signal: AbortSignal.timeout(15000) });
assert.equal(health.status, 200);
assert.equal((await health.json()).ok, true);
console.log('PASS: HTTP through verified proxy');
const socket = new WebSocket(new URL('/ws', origin).href.replace('http:', 'ws:'), { handshakeTimeout: 15000 });
socket.on('error', () => {});
try {
  await once(socket, 'open');
  for (let i = 0; i < 12; i++) {
    const bytes = randomBytes(1500);
    const message = once(socket, 'message', { signal: AbortSignal.timeout(10000) });
    socket.send(bytes);
    const [received, binary] = await message;
    assert(binary);
    assert.deepEqual(received, bytes);
    const pong = once(socket, 'pong', { signal: AbortSignal.timeout(10000) });
    socket.ping();
    await pong;
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  console.log('PASS: binary WebSocket and heartbeats for 60 seconds');
  const egress = await fetch(new URL('/egress', origin), { signal: AbortSignal.timeout(15000) });
  assert.equal(egress.status, 200);
  assert.equal((await egress.json()).reachable, true);
  console.log('PASS: outbound HTTPS to Tuft relay');
} finally {
  socket.terminate();
}
