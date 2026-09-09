import { readdir, readFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { execFileSync } from 'node:child_process'

const CODE_EXT = /\.(py|js|mjs|cjs|ts|tsx)$/i
const SKIP = /(^|\/)(\.git|node_modules|dist|build|coverage|\.venv|venv|vendor)(\/|$)/
const MAX_FILES = 300
const MAX_BYTES = 180_000

async function walk(root, dir, out) {
  if (out.length >= MAX_FILES) return
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const abs = join(dir, entry.name)
    const rel = relative(root, abs).replaceAll('\\', '/')
    if (SKIP.test(rel)) continue
    if (entry.isDirectory()) await walk(root, abs, out)
    else if (entry.isFile() && CODE_EXT.test(rel)) out.push({ abs, rel })
    if (out.length >= MAX_FILES) break
  }
}

export async function collectLocalRepository(root) {
  const found = []
  await walk(root, root, found)
  const files = {}
  for (const item of found) {
    const buffer = await readFile(item.abs)
    if (buffer.byteLength <= MAX_BYTES) files[item.rel] = buffer.toString('utf8')
  }
  let revision = null
  try { revision = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim() } catch {}
  return {
    subject: { id: root, name: root },
    repository_url: null,
    revision,
    observed_at: new Date().toISOString(),
    files,
    files_selected: Object.keys(files).length,
  }
}
