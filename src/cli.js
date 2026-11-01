import { readFile, writeFile, mkdir, appendFile } from 'node:fs/promises'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { createDpapiStore, assertName } from './store.js'
import { createBroker, validatePolicy } from './broker.js'

const ROOT = process.env.SECRETS_ROOT ?? join(homedir(), '.ecc', 'secrets')
const VAULT = join(ROOT, 'vault')
const POLICY = join(ROOT, 'policy.json')
const AUDIT = join(ROOT, 'audit.log')

async function loadPolicy() {
  try {
    return validatePolicy(JSON.parse(await readFile(POLICY, 'utf8')))
  } catch (err) {
    if (err.code === 'ENOENT') return {}
    throw err
  }
}

async function savePolicy(policy) {
  await mkdir(ROOT, { recursive: true })
  await writeFile(POLICY, JSON.stringify(validatePolicy(policy), null, 2), 'utf8')
}

const store = createDpapiStore(VAULT)

async function main([cmd, ...args]) {
  if (cmd === 'list') {
    const broker = createBroker({ store, policy: await loadPolicy() })
    const items = await broker.list()
    if (items.length === 0) return console.log('no secrets stored')
    for (const i of items) console.log(`${i.name}  →  ${i.allowedHosts.join(', ') || '(no policy)'}  ${i.description}`)
    return
  }

  if (cmd === 'allow') {
    const [name, host, ...desc] = args
    assertName(name)
    if (!host) throw new Error('usage: allow <name> <host> [description]')
    const policy = await loadPolicy()
    const current = policy[name]?.allowedHosts ?? []
    policy[name] = {
      allowedHosts: [...new Set([...current, host])],
      description: desc.join(' ') || policy[name]?.description || '',
    }
    await savePolicy(policy)
    return console.log(`policy: ${name} → ${policy[name].allowedHosts.join(', ')}`)
  }

  if (cmd === 'revoke') {
    const [name, host] = args
    assertName(name)
    const policy = await loadPolicy()
    if (!policy[name]) throw new Error(`no policy for "${name}"`)
    policy[name].allowedHosts = policy[name].allowedHosts.filter((h) => h !== host)
    if (policy[name].allowedHosts.length === 0) delete policy[name]
    await savePolicy(policy)
    return console.log(`revoked ${host} from ${name}`)
  }

  if (cmd === 'remove') {
    const [name] = args
    assertName(name)
    await store.remove(name)
    const policy = await loadPolicy()
    delete policy[name]
    await savePolicy(policy)
    return console.log(`removed ${name}`)
  }

  if (cmd === 'call') {
    const [name, url, method = 'GET'] = args
    if (!name || !url) throw new Error('usage: call <name> <https-url> [METHOD]')
    const broker = createBroker({
      store,
      policy: await loadPolicy(),
      audit: (e) => appendFile(AUDIT, JSON.stringify(e) + '\n', 'utf8'),
    })
    const res = await broker.use({
      url,
      method,
      headers: { Authorization: `Bearer {{secret:${name}}}` },
    })
    console.log(`status ${res.status}${res.truncated ? ' (truncated)' : ''}`)
    console.log(res.body.slice(0, 2000))
    return
  }

  console.log([
    'usage:',
    '  node src/cli.js list',
    '  node src/cli.js allow <name> <host> [description]',
    '  node src/cli.js revoke <name> <host>',
    '  node src/cli.js remove <name>',
    '  node src/cli.js call <name> <https-url> [METHOD]',
    '  powershell -File set-secret.ps1 -Name <name>      (to store a value, hidden input)',
  ].join('\n'))
}

main(process.argv.slice(2)).catch((err) => {
  console.error(`error: ${err.message}`)
  process.exitCode = 1
})
