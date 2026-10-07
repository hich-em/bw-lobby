import { createServer } from 'node:http';
import { attachSignaling } from './server/signaling.mjs';

const port = Number(process.env.PORT) || 3000;
const server = createServer((req, res) => {
  const path = new URL(req.url ?? '/', 'http://x').pathname;
  if (path === '/signal/health') {
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(signaling.health()));
    return;
  }
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('Brood War co-op lobby service is running. WebSocket endpoint: /signal');
});
const signaling = attachSignaling(server, { log: (l) => console.log(`[signal] ${l}`) });
server.listen(port, '0.0.0.0', () => console.log(`Lobby service on port ${port} (/signal)`));
