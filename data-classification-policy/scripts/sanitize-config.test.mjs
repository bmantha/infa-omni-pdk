// Copyright 2026 Salesforce, Inc. All rights reserved.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { sanitizeConfig } from './sanitize-config.mjs';
import { generateConfig } from './generate-config.mjs';

const types = 'use serde::Deserialize;\n#[derive(Deserialize)]\npub struct Config {}\n';
const init = `#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.cdgc_base_api_url)?;
    abi.service_create(config.cdgc_login_url)?;
    abi.setup()?;
    Ok(())
}
`;

test('removes the entire generated initializer and preserves config types', () => {
  assert.equal(sanitizeConfig(types + init), types);
  assert.equal(sanitizeConfig((types + init).replaceAll('\n', '\r\n')), types.replaceAll('\n', '\r\n'));
});

test('rejects generator drift, duplicate entrypoints and unexpected trailing code', () => {
  for (const source of [types, types + init + init, types + init + 'fn extra() {}',
    types + init.replace('fn init(', 'fn changed('),
    types + init.replace('abi.setup()?;', 'log_config(); abi.setup()?;'),
    types + init.replace('abi.setup()?;', 'abi.service_create(config.new_service)?; abi.setup()?;'),
    types + init.replace('abi.service_create(config.cdgc_login_url)?;', ''),
    types + init.replace('config.cdgc_login_url', 'config.other_login_url'),
    types + 'fn get_configuration() {}\n' + init]) {
    assert.throws(() => sanitizeConfig(source), /Unexpected config-gen output/);
  }
});

test('atomic generation preserves safe output until validation and fails closed on errors', () => {
  const directory = mkdtempSync(join(tmpdir(), 'classification-generation-'));
  try {
    const destination = join(directory, 'config.rs');
    writeFileSync(destination, types);
    generateConfig('unused', destination, temporary => {
      writeFileSync(temporary, types + init);
      assert.equal(readFileSync(destination, 'utf8'), types);
    });
    assert.equal(readFileSync(destination, 'utf8'), types);
    for (const generate of [
      temporary => writeFileSync(temporary, types + init.replace('fn init(', 'fn changed(')),
      () => { throw new Error('generator failed'); },
    ]) {
      assert.throws(() => generateConfig('unused', destination, generate));
      assert.match(readFileSync(destination, 'utf8'), /^compile_error!\(/);
      assert.doesNotMatch(readFileSync(destination, 'utf8'), /get_configuration|entrypoint_flex/);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('the real pinned generator preserves fields and expected services', () => {
  const directory = mkdtempSync(join(tmpdir(), 'classification-real-generation-'));
  try {
    const definition = fileURLToPath(new URL('../definition/gcl.yaml', import.meta.url));
    const file = join(directory, 'config.rs');
    const generated = spawnSync('cargo', ['anypoint', 'config-gen', '-p', '-m', definition, '-o', file],
      { encoding: 'utf8', timeout: 120_000 });
    assert.equal(generated.status, 0, generated.stderr);
    const original = readFileSync(file, 'utf8');
    const sanitized = sanitizeConfig(original);
    assert.match(sanitized, /pub cdgc_base_api_url: pdk::hl::Service/);
    assert.match(sanitized, /pub cdgc_login_url: pdk::hl::Service/);
    assert.match(sanitized, /pub cdgc_org_password: String/);
    assert.match(sanitized, /allowInsecureLocalServices/);
    assert.equal(sanitized, original.slice(0, original.indexOf('#[pdk::hl::entrypoint_flex]')));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('missing Node fails before generation and leaves existing safe config unchanged', () => {
  const directory = mkdtempSync(join(tmpdir(), 'classification-no-node-'));
  try {
    mkdirSync(join(directory, 'src/generated'), { recursive: true });
    const destination = join(directory, 'src/generated/config.rs');
    writeFileSync(destination, types);
    const result = spawnSync('/usr/bin/make', ['-f',
      fileURLToPath(new URL('../Makefile', import.meta.url)), 'build-asset-files',
      `DEFINITION_SRC_GCL_PATH=${fileURLToPath(new URL('../definition/gcl.yaml', import.meta.url))}`,
      'ANYPOINT_METADATA_JSON={}'],
      { cwd: directory, env: { ...process.env, PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Node is required before configuration generation/);
    assert.equal(readFileSync(destination, 'utf8'), types);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI replaces unsafe output with a compilation failure on generator drift', () => {
  const directory = mkdtempSync(join(tmpdir(), 'classification-config-'));
  try {
    const file = join(directory, 'config.rs');
    writeFileSync(file, types + init.replace('fn init(', 'fn changed('));
    const result = spawnSync(process.execPath,
      [fileURLToPath(new URL('./sanitize-config.mjs', import.meta.url)), file]);
    assert.equal(result.status, 1);
    assert.match(readFileSync(file, 'utf8'), /^compile_error!\(/);
    assert.doesNotMatch(readFileSync(file, 'utf8'), /get_configuration|entrypoint_flex/);
    writeFileSync(file, types + init);
    const regenerated = spawnSync(process.execPath,
      [fileURLToPath(new URL('./sanitize-config.mjs', import.meta.url)), file]);
    assert.equal(regenerated.status, 0);
    assert.equal(readFileSync(file, 'utf8'), types);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
