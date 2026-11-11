// Copyright 2026 Salesforce, Inc. All rights reserved.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// Fail closed on generator drift rather than retaining a configuration-logging initializer.
const generatedInit = /\n#\[pdk::hl::entrypoint_flex\]\s*fn init\(abi: &dyn pdk::flex_abi::api::FlexAbi\) -> Result<\(\), anyhow::Error> \{\s*let config: Config = serde_json::from_slice\(abi.get_configuration\(\)\)\s*\.map_err\(\|err\| \{\s*anyhow::anyhow!\(\s*"Failed to parse configuration '\{\}'. Cause: \{\}",\s*String::from_utf8_lossy\(abi.get_configuration\(\)\), err\s*\)\s*\}\)\?;\s*(?:abi.service_create\(config\.[a-z_]+\)\?;\s*)*abi.setup\(\)\?;\s*Ok\(\(\)\)\s*\}\s*$/;

export function sanitizeConfig(source) {
  const registrations = [...source.matchAll(/abi\.service_create\(config\.([a-z_]+)\)\?;/g)]
    .map(match => match[1]);
  if (registrations.join(',') !== 'cdgc_base_api_url,cdgc_login_url') {
    throw new Error('Unexpected config-gen output; service registration changed');
  }
  const sanitized = source.replace(generatedInit, '\n');
  if (sanitized === source || /entrypoint_flex|FlexAbi|get_configuration/.test(sanitized)) {
    throw new Error('Unexpected config-gen output; refusing generated Flex initialization');
  }
  return sanitized;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const file = process.argv[2];
  if (!file || process.argv.length !== 3) {
    throw new Error('Usage: node sanitize-config.mjs <generated-config.rs>');
  }
  const source = readFileSync(file, 'utf8');
  try {
    writeFileSync(file, sanitizeConfig(source));
  } catch (error) {
    // A failed build must not leave the unsafe generated initializer available to cargo.
    writeFileSync(file, 'compile_error!("config-gen sanitizer failed; regenerate configuration");\n');
    throw error;
  }
}
