import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// every test file imports this first: a throwaway data dir and the env the config wants
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'argos-test-'));
process.env.SESSION_SECRET ??= 'test';
process.env.LAPI_USER ??= 'test';
process.env.LAPI_PASSWORD ??= 'test';
process.env.LAPI_URL ??= 'http://127.0.0.1:1';
