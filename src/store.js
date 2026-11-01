import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { readFile, readdir, unlink } from 'node:fs/promises'
import { join } from 'node:path'

const run = promisify(execFile)

export const NAME_RE = /^[a-z0-9][a-z0-9_-]{1,63}$/

export function assertName(name) {
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    throw new Error('invalid secret name')
  }
}

/**
 * Reads secrets written by set-secret.ps1. Values are encrypted with Windows DPAPI,
 * so only the current Windows user on this machine can decrypt them.
 */
export function createDpapiStore(dir) {
  const fileOf = (name) => join(dir, `${name}.dpapi`)

  async function decrypt(blob) {
    const script = [
      '$s = ConvertTo-SecureString -String $env:BROKER_BLOB',
      '$p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)',
      'try {',
      '  [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p)',
      '} finally {',
      '  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p)',
      '}',
    ].join('\n')
    const { stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { env: { ...process.env, BROKER_BLOB: blob }, windowsHide: true },
    )
    return stdout.replace(/\r?\n$/, '')
  }

  return {
    async get(name) {
      assertName(name)
      const blob = await readFile(fileOf(name), 'utf8')
      return decrypt(blob.trim())
    },
    async names() {
      const files = await readdir(dir).catch(() => [])
      return files
        .filter((f) => f.endsWith('.dpapi'))
        .map((f) => f.slice(0, -'.dpapi'.length))
        .filter((n) => NAME_RE.test(n))
        .sort()
    },
    async remove(name) {
      assertName(name)
      await unlink(fileOf(name))
    },
  }
}
