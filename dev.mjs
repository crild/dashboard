// Local development: static file server for index.html plus `wrangler dev` for
// the Worker, under one Ctrl+C. Dev tooling only — nothing here ships to Pages,
// which still serves index.html as a plain static file with no build step.
//
//   node dev.mjs          dashboard on :8765, Worker on :8787
//
// index.html points itself at 127.0.0.1:8787 whenever it is served from
// localhost, so the two halves find each other automatically.

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const SITE_PORT = 8765;
const WORKER_PORT = 8787;
const ROOT = process.cwd();

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
};

const site = createServer(async (req, res) => {
  const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  // normalize() collapses ../ before it can escape the repo directory.
  const path = join(ROOT, normalize(rel === '/' ? '/index.html' : rel));
  if (!path.startsWith(ROOT)) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  try {
    const body = await readFile(path);
    res.writeHead(200, {
      'Content-Type': TYPES[extname(path).toLowerCase()] ?? 'application/octet-stream',
      // Always re-read from disk, so a reload shows the edit just made.
      'Cache-Control': 'no-store',
    }).end(body);
  } catch {
    res.writeHead(404).end('Not found');
  }
});

site.listen(SITE_PORT, '127.0.0.1', () => {
  console.log(`dashboard  http://127.0.0.1:${SITE_PORT}`);
  console.log(`worker     http://127.0.0.1:${WORKER_PORT}`);
});

const worker = spawn(
  process.platform === 'win32' ? 'npx.cmd' : 'npx',
  ['wrangler', 'dev', '--port', String(WORKER_PORT), '--local'],
  { stdio: 'inherit', shell: process.platform === 'win32' }
);

worker.on('exit', code => {
  console.log(`wrangler exited (${code}) — stopping dev server`);
  site.close();
  process.exit(code ?? 0);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { worker.kill(); site.close(); process.exit(0); });
}
