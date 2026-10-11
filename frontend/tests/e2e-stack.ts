import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * Gedeelde e2e-opzet (v0.2.0-Koblitz): eigen backend (uvicorn, vrije poort, tijdelijke DB) en een
 * statische frontend (vrije poort). Nooit de productie-backend op 3997 gebruiken (HC55).
 *
 * Omgeving:
 *   HS_PYTHON       python met de backend-deps (default: python3)
 *   HS_E2E_TMPDIR   map voor de tijdelijke DB/vaults (default: os.tmpdir())
 */

export const REPO = resolve(__dirname, '..', '..');
export const PYTHON = process.env.HS_PYTHON || 'python3';

export interface Stack {
  apiPort: number;
  webPort: number;
  tmp: string;
  dbPath: string;
  log: () => string;
  stop: () => void;
}

export function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once('error', fail);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      s.close(() => ok(port));
    });
  });
}

export async function waitFor(url: string, logFn: () => string = () => '', timeoutMs = 30_000): Promise<void> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      /* nog niet klaar */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`${url} kwam niet op binnen ${timeoutMs} ms.\n--- backend-log ---\n${logFn()}`);
}

/** Start backend + frontend. De frontend praat via localStorage 'horsesafe.devApiPort' met de backend. */
export async function startStack(
  prefix: string,
  extraEnv: (origin: string) => Record<string, string> = () => ({}),
): Promise<Stack> {
  const tmp = mkdtempSync(join(process.env.HS_E2E_TMPDIR || tmpdir(), prefix));
  const apiPort = await freePort();
  const webPort = await freePort();
  const origin = `http://localhost:${webPort}`;
  const dbPath = join(tmp, 'horsesafe.db');
  let backendLog = '';
  const backend: ChildProcess = spawn(PYTHON, ['-m', 'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', String(apiPort)], {
    cwd: REPO,
    env: {
      PATH: process.env.PATH || '/usr/bin:/bin',
      HOME: tmp,
      HORSESAFE_JWT_SECRET: randomBytes(32).toString('hex'),
      HORSESAFE_COOKIE_SECURE: 'false',
      HORSESAFE_CORS_ORIGINS: origin,
      HORSESAFE_RATE_LIMIT_ENABLED: 'false',
      HORSESAFE_DB_PATH: dbPath,
      HORSESAFE_VAULTS_DIR: join(tmp, 'vaults'),
      HORSESAFE_PUBLIC_URL: origin,
      ...extraEnv(origin),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const onLog = (b: Buffer) => { backendLog = (backendLog + b.toString()).slice(-20_000); };
  backend.stdout?.on('data', onLog);
  backend.stderr?.on('data', onLog);
  const frontend: ChildProcess = spawn(PYTHON, ['-m', 'http.server', String(webPort), '--bind', '127.0.0.1', '--directory', join(REPO, 'frontend')], {
    stdio: 'ignore',
  });
  const log = () => backendLog;
  const stop = () => {
    backend.kill('SIGTERM');
    frontend.kill('SIGTERM');
    rmSync(tmp, { recursive: true, force: true });
  };
  try {
    await waitFor(`http://127.0.0.1:${apiPort}/health`, log);
    await waitFor(`http://127.0.0.1:${webPort}/vault.html`, log);
  } catch (e) {
    stop();
    throw e;
  }
  return { apiPort, webPort, tmp, dbPath, log, stop };
}

// Minimale TOTP (RFC 6238, SHA-1, 30 s) — zelfde aanpak als mfa.spec.ts
export async function totpCode(secretBase32: string, at = Date.now()): Promise<string> {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secretBase32.replace(/=+$/, '').toUpperCase()) bits += ALPHABET.indexOf(c).toString(2).padStart(5, '0');
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setUint32(4, Math.floor(at / 1000 / 30), false);
  const key = await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const o = sig[sig.length - 1] & 0xf;
  const code = ((sig[o] & 0x7f) << 24) | (sig[o + 1] << 16) | (sig[o + 2] << 8) | sig[o + 3];
  return (code % 1_000_000).toString().padStart(6, '0');
}

/** Een code uit een nieuw 30-s-venster (servers weigeren vaak hergebruik van dezelfde code). */
export async function freshTotp(secret: string, used: Set<string>): Promise<string> {
  for (;;) {
    const c = await totpCode(secret);
    if (!used.has(c)) { used.add(c); return c; }
    await new Promise((r) => setTimeout(r, 1000));
  }
}
