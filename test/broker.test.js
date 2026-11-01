import test from 'node:test'
import assert from 'node:assert/strict'
import { createBroker, validatePolicy } from '../src/broker.js'

const SECRET = 'sk-test-SUPER-SECRET-123'

function fakeStore(values = { openrouter: SECRET }) {
  return {
    async get(name) {
      if (!(name in values)) throw new Error('not found')
      return values[name]
    },
    async names() {
      return Object.keys(values)
    },
  }
}

const policy = validatePolicy({
  openrouter: { allowedHosts: ['openrouter.ai'], description: 'LLM gateway' },
})

function recordingFetch(responseText = '{"ok":true}', status = 200) {
  const calls = []
  const fn = async (url, init) => {
    calls.push({ url, init })
    return new Response(responseText, { status })
  }
  return { fn, calls }
}

test('list returns names and policy, never values', async () => {
  const b = createBroker({ store: fakeStore(), policy, fetchFn: recordingFetch().fn })
  const items = await b.list()
  assert.equal(items.length, 1)
  assert.equal(items[0].name, 'openrouter')
  assert.deepEqual(items[0].allowedHosts, ['openrouter.ai'])
  assert.ok(!JSON.stringify(items).includes(SECRET))
})

test('placeholder is filled only in the outgoing request', async () => {
  const rec = recordingFetch()
  const b = createBroker({ store: fakeStore(), policy, fetchFn: rec.fn })
  const res = await b.use({
    url: 'https://openrouter.ai/api/v1/models',
    headers: { Authorization: 'Bearer {{secret:openrouter}}' },
  })
  assert.equal(res.status, 200)
  assert.equal(rec.calls[0].init.headers.Authorization, `Bearer ${SECRET}`)
})

test('secret echoed by the remote side is redacted', async () => {
  const rec = recordingFetch(`echo: ${SECRET} done`)
  const b = createBroker({ store: fakeStore(), policy, fetchFn: rec.fn })
  const res = await b.use({
    url: 'https://openrouter.ai/x',
    headers: { Authorization: 'Bearer {{secret:openrouter}}' },
  })
  assert.ok(!res.body.includes(SECRET))
  assert.ok(res.body.includes('[REDACTED:openrouter]'))
})

test('lookalike host is rejected and nothing is sent', async () => {
  const rec = recordingFetch()
  const b = createBroker({ store: fakeStore(), policy, fetchFn: rec.fn })
  await assert.rejects(
    () => b.use({ url: 'https://evil-openrouter.ai/x', headers: { A: '{{secret:openrouter}}' } }),
    /not allowed/,
  )
  assert.equal(rec.calls.length, 0)
})

test('subdomain of an allowed host is accepted', async () => {
  const rec = recordingFetch()
  const b = createBroker({ store: fakeStore(), policy, fetchFn: rec.fn })
  await b.use({ url: 'https://api.openrouter.ai/x', headers: { A: '{{secret:openrouter}}' } })
  assert.equal(rec.calls.length, 1)
})

test('plain http is rejected', async () => {
  const rec = recordingFetch()
  const b = createBroker({ store: fakeStore(), policy, fetchFn: rec.fn })
  await assert.rejects(
    () => b.use({ url: 'http://openrouter.ai/x', headers: { A: '{{secret:openrouter}}' } }),
    /only https/,
  )
  assert.equal(rec.calls.length, 0)
})

test('secret without policy is rejected', async () => {
  const rec = recordingFetch()
  const b = createBroker({ store: fakeStore({ other: 'v' }), policy, fetchFn: rec.fn })
  await assert.rejects(
    () => b.use({ url: 'https://openrouter.ai/x', headers: { A: '{{secret:other}}' } }),
    /no policy/,
  )
  assert.equal(rec.calls.length, 0)
})

test('request without any placeholder is rejected', async () => {
  const b = createBroker({ store: fakeStore(), policy, fetchFn: recordingFetch().fn })
  await assert.rejects(() => b.use({ url: 'https://openrouter.ai/x' }), /no secret referenced/)
})

test('network error does not leak the secret or the URL', async () => {
  const b = createBroker({
    store: fakeStore(),
    policy,
    fetchFn: async () => {
      throw new TypeError(`failed for ${SECRET}`)
    },
  })
  await assert.rejects(
    () => b.use({ url: 'https://openrouter.ai/x?k={{secret:openrouter}}' }),
    (err) => {
      assert.equal(err.message, 'request failed')
      assert.ok(!err.message.includes(SECRET))
      return true
    },
  )
})

test('audit records host, names and status, never values', async () => {
  const lines = []
  const b = createBroker({
    store: fakeStore(),
    policy,
    fetchFn: recordingFetch().fn,
    audit: (e) => lines.push(e),
    now: () => new Date('2026-11-01T00:00:00Z'),
  })
  await b.use({ url: 'https://openrouter.ai/x', headers: { A: 'Bearer {{secret:openrouter}}' } })
  assert.equal(lines.length, 1)
  assert.deepEqual(lines[0].secrets, ['openrouter'])
  assert.equal(lines[0].status, 200)
  assert.ok(!JSON.stringify(lines).includes(SECRET))
})

test('large response is truncated', async () => {
  const big = 'a'.repeat(70 * 1024)
  const b = createBroker({ store: fakeStore(), policy, fetchFn: recordingFetch(big).fn })
  const res = await b.use({ url: 'https://openrouter.ai/x', headers: { A: '{{secret:openrouter}}' } })
  assert.equal(res.truncated, true)
  assert.ok(res.body.length <= 64 * 1024)
})

test('validatePolicy rejects bad entries', () => {
  assert.throws(() => validatePolicy({ 'Bad Name': { allowedHosts: ['a.com'] } }))
  assert.throws(() => validatePolicy({ ok: { allowedHosts: [] } }))
  assert.throws(() => validatePolicy({ ok: { allowedHosts: ['https://a.com'] } }))
})
