// Copyright 2026 Salesforce, Inc. All rights reserved.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));

test('registration uses the host UID and GID only on POSIX', () => {
  for (const os of ['', 'Windows_NT']) {
    for (const target of ['playground/config/registration.yaml', 'tests/config/registration.yaml']) {
      const result = spawnSync('make', ['-B', '-n', target, `OS=${os}`, 'SHELL=/bin/sh'],
        { cwd: root, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      const command = result.stdout.split('\n').find(line => line.startsWith('docker run '));
      assert.ok(command, 'registration must invoke Docker');
      if (os === 'Windows_NT') {
        assert.doesNotMatch(command, /--user|\bid\b/);
      } else {
        assert.ok(command.includes('--user "$(id -u):$(id -g)"'), command);
      }
    }
  }
});

test('demo pins its fixture and disables dotenv for startup and cleanup', () => {
  const directory = mkdtempSync(join(tmpdir(), 'classification-demo-'));
  try {
    mkdirSync(join(directory, 'config'));
    copyFileSync(join(root, 'playground/demo.sh'), join(directory, 'demo.sh'));
    copyFileSync(join(root, 'playground/config/api.yaml'), join(directory, 'config/api.yaml'));
    writeFileSync(join(directory, '.env'), 'CLASSIFICATION_API_CONFIG=./private/api.yaml\nCOMPOSE_FILE=private.yaml\n');
    writeFileSync(join(directory, 'docker-compose.yaml'), 'services: {}\n');
    const log = join(directory, 'calls.jsonl');
    const fakeDocker = join(directory, 'docker');
    writeFileSync(fakeDocker, `#!${process.execPath}\n` +
      `require('node:fs').appendFileSync(process.env.TEST_LOG, JSON.stringify({args:process.argv.slice(2), config:process.env.CLASSIFICATION_API_CONFIG})+'\\n');\n` +
      `process.exit(process.argv.includes('up') ? 7 : 0);\n`);
    chmodSync(fakeDocker, 0o700);
    const env = { ...process.env, PATH: `${directory}:${process.env.PATH}`, TEST_LOG: log };
    delete env.CLASSIFICATION_API_CONFIG;
    delete env.API_CONFIG;
    for (const args of [[], ['--cleanup']]) {
      const result = spawnSync(join(directory, 'demo.sh'), args, { cwd: directory, env, encoding: 'utf8' });
      assert.equal(result.status, args.length ? 0 : 7, result.stderr);
    }
    const calls = readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(calls.length, 2);
    for (const call of calls) {
      assert.equal(call.config, join(directory, 'config/api.yaml'));
      assert.deepEqual(call.args.slice(0, 5), ['compose', '--env-file', '/dev/null', '-f', join(directory, 'docker-compose.yaml')]);
    }
    const fixture = readFileSync(join(directory, 'config/api.yaml'), 'utf8');
    const altered = [
      fixture + '\n        cdgcLoginUrl: https://private.example\n',
      fixture + '\n        "cdgcLoginUrl": https://private.example\n',
      fixture.replace('        cdgcLoginUrl: http://cdgclogin',
        '        annotation: |\n          cdgcLoginUrl: http://cdgclogin\n        "cdgcLoginUrl": https://private.example'),
      fixture.replace('cdgcOrgPassword: dummy-cdgc-password', 'cdgcOrgPassword: private-password'),
    ];
    for (const config of altered) {
      writeFileSync(join(directory, 'config/api.yaml'), config);
      for (const optimize of ['0', '1']) {
        for (const args of [[], ['--cleanup']]) {
          const invalid = spawnSync(join(directory, 'demo.sh'), args,
            { cwd: directory, env: { ...env, PYTHONOPTIMIZE: optimize }, encoding: 'utf8' });
          assert.equal(invalid.status, 1, invalid.stderr);
          assert.match(invalid.stderr, /reviewed, byte-exact local mock fixture/);
          assert.equal(readFileSync(log, 'utf8').trim().split('\n').length, 2,
            'invalid fixture must never invoke Docker');
        }
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('relative API_CONFIG is resolved once for validation, patching and Compose', () => {
  const result = spawnSync('make', ['-n', 'run', '-o', 'build', '-o', 'playground/config/registration.yaml',
    'API_CONFIG=playground/private/api.yaml', 'POLICY_REF_NAME=test-policy', 'DEFINITION_GCL_PATH=test-definition',
    'DEFINITION_NAMESPACE=default', 'CRATE_NAME=test'], { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const selected = resolve(root, 'playground/private/api.yaml');
  assert.ok(result.stdout.includes(`test -f "${selected}"`));
  assert.ok(result.stdout.includes(`patch-api -o "${selected}"`));
  assert.equal(result.stdout.split(`CLASSIFICATION_API_CONFIG="${selected}"`).length - 1, 2);
  const compose = readFileSync(join(root, 'playground/docker-compose.yaml'), 'utf8');
  assert.match(compose, /type: bind\s+source: \$\{CLASSIFICATION_API_CONFIG[^\n]+\s+target: [^\n]+\s+read_only: true\s+bind:\s+create_host_path: false/);
});
