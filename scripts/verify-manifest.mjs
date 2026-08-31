#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import { verifyAssuranceManifest } from '../core/trust-kernel.mjs'

const file = process.argv[2]
if (!file) {
  console.error('Usage: node scripts/verify-manifest.mjs <manifest.json>')
  process.exit(2)
}

const manifest = JSON.parse(await readFile(file, 'utf8'))
const result = verifyAssuranceManifest(manifest)
console.log(JSON.stringify(result, null, 2))
process.exit(result.valid ? 0 : 1)
