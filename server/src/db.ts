import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { config } from './config.js';

mkdirSync(config.dataDir, { recursive: true });
export const db = new DatabaseSync(join(config.dataDir, 'argos.db'));

db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    totp_secret TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    totp_ok INTEGER NOT NULL DEFAULT 0,
    ip TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
  );
  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    hash TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    created_by TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_used_at INTEGER,
    last_ip TEXT
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

export function getSetting<T>(key: string, fallback: T): T {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
  return row ? (JSON.parse(row.value) as T) : fallback;
}

export function setSetting(key: string, value: unknown): void {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, JSON.stringify(value));
}

export function audit(username: string | null, action: string, target?: string, detail?: unknown): void {
  db.prepare('INSERT INTO audit (ts, username, action, target, detail) VALUES (?, ?, ?, ?, ?)')
    .run(Date.now(), username, action, target ?? null, detail === undefined ? null : JSON.stringify(detail));
}
