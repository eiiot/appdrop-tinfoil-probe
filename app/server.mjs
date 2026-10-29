import http from 'node:http';
import https from 'node:https';
import { WebSocketServer } from 'ws';

// This probe accepts only disposable test bytes. No device or account state.
const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  if (req.method === 'GET' && req.url === '/health') {
    res.end(JSON.stringify({ ok: true, probe: 'appdrop-transport-v1' }));
  } else if (req.method === 'GET' && req.url === '/egress') {
    const outbound = https.get('https://tuft-rendezvous.fly.dev/', { timeout: 10000 }, upstream => {
      upstream.resume();
      res.end(JSON.stringify({ reachable: true, status: upstream.statusCode }));
    });
    outbound.on('timeout', () => outbound.destroy(new Error('timeout')));
    outbound.on('error', () => {
      res.writeHead(502);
      res.end(JSON.stringify({ reachable: false }));
    });
  } else {
    res.writeHead(404);
    res.end('{}');
  }
});
const sockets = new WebSocketServer({ noServer: true, maxPayload: 65536, perMessageDeflate: false });
server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') return socket.destroy();
  sockets.handleUpgrade(req, socket, head, ws => sockets.emit('connection', ws));
});
sockets.on('connection', ws => {
  ws.on('error', () => {});
  ws.on('message', (bytes, isBinary) => ws.send(bytes, { binary: isBinary }));
});
server.listen(Number(process.env.PORT || 8080), '0.0.0.0');
