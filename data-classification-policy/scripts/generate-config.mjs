// Copyright 2026 Salesforce, Inc. All rights reserved.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sanitizeConfig } from './sanitize-config.mjs';

export function generateConfig(definition, destination, generate = output => {
  const result = spawnSync('cargo', ['anypoint', 'config-gen', '-p', '-m', definition, '-o', output],
    { stdio: 'inherit', timeout: 120_000 });
  if (result.error || result.status !== 0) throw new Error('Configuration generator failed');
}) {
  destination = resolve(destination);
  // Same-directory rename keeps the unsafe initializer out of cargo's source tree.
  const directory = mkdtempSync(join(dirname(destination), '.config-gen-'));
  const temporary = join(directory, 'config.rs');
  try {
    generate(temporary);
    writeFileSync(temporary, sanitizeConfig(readFileSync(temporary, 'utf8')));
    renameSync(temporary, destination);
  } catch (error) {
    writeFileSync(temporary, 'compile_error!("config-gen failed; regenerate configuration");\n');
    renameSync(temporary, destination);
    throw error;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 4) throw new Error('Usage: node generate-config.mjs <gcl> <config.rs>');
  generateConfig(process.argv[2], process.argv[3]);
}
