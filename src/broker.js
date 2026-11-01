import { NAME_RE, assertName } from './store.js'

const MAX_RESPONSE_BYTES = 64 * 1024
const TIMEOUT_MS = 15_000
const PLACEHOLDER = /\{\{\s*secret:([a-z0-9][a-z0-9_-]{1,63})\s*\}\}/g

function placeholdersIn(text) {
  return [...String(text ?? '').matchAll(PLACEHOLDER)].map((m) => m[1])
}

function hostAllowed(host, allowedHosts) {
  return allowedHosts.some((h) => host === h || host.endsWith(`.${h}`))
}

/**
 * The model never receives a secret value. It passes templates such as
 * "Bearer {{secret:openrouter}}" and the broker substitutes the real value
 * only inside the outgoing request, then redacts the response.
 */
export function createBroker({ store, policy, fetchFn = fetch, audit = () => {}, now = () => new Date() }) {
  function ruleFor(name) {
    const rule = policy[name]
    if (!rule) throw new Error(`secret "${name}" has no policy`)
    return rule
  }

  async function list() {
    const names = await store.names()
    return names.map((name) => ({
      name,
      allowedHosts: policy[name]?.allowedHosts ?? [],
      description: policy[name]?.description ?? '',
    }))
  }

  async function use({ url, method = 'GET', headers = {}, body }) {
    let target
    try {
      target = new URL(url)
    } catch {
      throw new Error('invalid url')
    }
    if (target.protocol !== 'https:') throw new Error('only https is allowed')

    const referenced = new Set([
      ...placeholdersIn(url),
      ...Object.values(headers).flatMap(placeholdersIn),
      ...placeholdersIn(body),
    ])
    if (referenced.size === 0) throw new Error('no secret referenced')

    for (const name of referenced) {
      assertName(name)
      const rule = ruleFor(name)
      if (!hostAllowed(target.hostname, rule.allowedHosts)) {
        throw new Error(`host "${target.hostname}" is not allowed for secret "${name}"`)
      }
    }

    const values = new Map()
    for (const name of referenced) values.set(name, await store.get(name))

    const fill = (text) =>
      String(text ?? '').replace(PLACEHOLDER, (_, name) => values.get(name) ?? '')

    const outHeaders = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k, fill(v)]),
    )
    const outBody = body === undefined ? undefined : fill(body)
    const outUrl = fill(url)

    const entry = { at: now().toISOString(), host: target.hostname, method, secrets: [...referenced] }

    let res
    try {
      res = await fetchFn(outUrl, {
        method,
        headers: outHeaders,
        body: outBody,
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      })
    } catch (err) {
      await audit({ ...entry, status: 'network-error', reason: err?.name ?? 'Error' })
      throw new Error('request failed')
    }

    const raw = await res.text()
    const clipped = raw.length > MAX_RESPONSE_BYTES ? raw.slice(0, MAX_RESPONSE_BYTES) : raw
    let redacted = clipped
    for (const [name, value] of values) {
      if (value) redacted = redacted.split(value).join(`[REDACTED:${name}]`)
    }

    await audit({ ...entry, status: res.status })
    return { status: res.status, body: redacted, truncated: raw.length > MAX_RESPONSE_BYTES }
  }

  return { list, use }
}

export function validatePolicy(policy) {
  for (const [name, rule] of Object.entries(policy)) {
    if (!NAME_RE.test(name)) throw new Error(`invalid policy name: ${name}`)
    if (!Array.isArray(rule.allowedHosts) || rule.allowedHosts.length === 0) {
      throw new Error(`policy "${name}" needs allowedHosts`)
    }
    for (const h of rule.allowedHosts) {
      if (!/^[a-z0-9.-]+$/.test(h)) throw new Error(`invalid host in "${name}": ${h}`)
    }
  }
  return policy
}
