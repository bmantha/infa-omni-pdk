// Copyright 2026 Salesforce, Inc. All rights reserved.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { sanitizeConfig } from './sanitize-config.mjs';

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
    types + 'fn get_configuration() {}\n' + init]) {
    assert.throws(() => sanitizeConfig(source), /Unexpected config-gen output/);
  }
});

test('CLI replaces unsafe output with a compilation failure on generator drift', () => {
  const directory = mkdtempSync(join(tmpdir(), 'dq-config-'));
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
