// Copyright 2026 Salesforce, Inc. All rights reserved.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const launcher = fileURLToPath(new URL('./run-tests.mjs', import.meta.url));

test('launcher preserves exit status and reports failed startup', () => {
  const result = spawnSync(process.execPath, [launcher, '--', process.execPath, '-e', 'process.exit(7)'], { timeout: 3000 });
  assert.equal(result.status, 7);
  const missing = spawnSync(process.execPath, [launcher, '--', '/no-such-test-command'], { timeout: 3000 });
  assert.equal(missing.status, 1);
});

test('deadline kills TERM-resistant grandchildren even after their parent exits', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'classification-deadline-'));
  const heartbeat = join(directory, 'heartbeat');
  const pidFile = join(directory, 'pid');
  try {
    const grandchild = `const fs=require('node:fs'); fs.writeFileSync(${JSON.stringify(pidFile)},String(process.pid));
      process.on('SIGTERM',()=>{}); setInterval(()=>fs.appendFileSync(${JSON.stringify(heartbeat)},'x'),20);`;
    const parent = `require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(grandchild)}],{stdio:'inherit'});
      process.on('SIGTERM',()=>process.exit(0)); setInterval(()=>{},1000);`;
    const started = Date.now();
    const result = spawnSync(process.execPath,
      [launcher, '--timeout-ms', '500', '--grace-ms', '150', '--', process.execPath, '-e', parent],
      { timeout: 4000, encoding: 'utf8' });
    assert.equal(result.status, 124, result.stderr);
    assert.ok(Date.now() - started < 3000);
    assert.ok(existsSync(heartbeat), 'grandchild must have started');
    const stopped = readFileSync(heartbeat, 'utf8');
    await delay(150);
    assert.equal(readFileSync(heartbeat, 'utf8'), stopped, 'grandchild must not survive group escalation');
  } finally {
    if (existsSync(pidFile)) {
      try { process.kill(Number(readFileSync(pidFile, 'utf8')), 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test('external termination also cleans the process group and returns 143', async () => {
  const child = spawn(process.execPath, [launcher, '--timeout-ms', '3000', '--grace-ms', '100', '--',
    process.execPath, '-e', 'process.on("SIGTERM",()=>{}); setInterval(()=>{},1000)'], { stdio: 'ignore' });
  const exit = new Promise(resolve => child.on('exit', (code, signal) => resolve({ code, signal })));
  try {
    await delay(200);
    child.kill('SIGTERM');
    assert.deepEqual(await Promise.race([exit, delay(3000).then(() => { throw new Error('termination hung'); })]),
      { code: 143, signal: null });
  } finally {
    child.kill('SIGKILL');
  }
});
