// Copyright 2026 Salesforce, Inc. All rights reserved.
import { spawn } from 'node:child_process';

if (process.platform === 'win32') throw new Error('Process-group deadlines require a POSIX host');
const args = process.argv.slice(2);
let timeout = 600_000;
let grace = 10_000;
while (args[0] !== '--' && args.length) {
  const option = args.shift();
  const value = Number(args.shift());
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error('Deadline must be a positive integer');
  if (option === '--timeout-ms') timeout = value;
  else if (option === '--grace-ms') grace = value;
  else throw new Error('Unknown deadline option');
}
if (args.shift() !== '--' || !args.length) throw new Error('Usage: run-tests.mjs [--timeout-ms N] [--grace-ms N] -- command [args]');
const child = spawn(args.shift(), args, { detached: true, stdio: 'inherit' });
let stopping = false;
let exited = false;
let exitCode = 1;
let deadline;
let escalation;

function signalGroup(signal) {
  try { process.kill(-child.pid, signal); }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
}

function stop(code) {
  if (stopping || !child.pid) return;
  stopping = true;
  exitCode = code;
  clearTimeout(deadline);
  signalGroup('SIGTERM');
  // Escalate even if cargo exits: a test or Docker child may still own the group.
  escalation = setTimeout(() => {
    signalGroup('SIGKILL');
    escalation = undefined;
    if (exited) process.exitCode = exitCode;
  }, grace);
}

child.on('spawn', () => {
  deadline = setTimeout(() => {
    console.error(`Test command exceeded ${timeout}ms; terminating its process group`);
    stop(124);
  }, timeout);
});
child.on('error', error => {
  console.error(`Cannot launch test command: ${error.code}`);
  clearTimeout(deadline);
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  exited = true;
  if (!stopping) {
    clearTimeout(deadline);
    process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1);
  } else if (!escalation) process.exitCode = exitCode;
});
process.on('SIGINT', () => stop(130));
process.on('SIGTERM', () => stop(143));
