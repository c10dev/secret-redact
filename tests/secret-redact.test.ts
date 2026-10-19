import type { ToolCallResult } from 'claude-code'
import { type Engine, describe, expect, mock, test } from 'claude-code/testing'
import { redact, redactValue } from '../hooks/redact'

// Fake values only: every one is built here from repeated characters or a
// made-up payload. None of them is or was a real credential.

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const b64url = (text: string): string => {
  const bytes = new TextEncoder().encode(text)
  let out = ''
  let buffer = 0
  let bits = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 6) {
      bits -= 6
      out += B64URL[(buffer >> bits) & 63]
    }
  }
  if (bits > 0) out += B64URL[(buffer << (6 - bits)) & 63]
  return out
}
const fakeJwt = (role: string): string =>
  `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(`{"iss":"supabase","ref":"fakefakefake","role":"${role}","iat":1,"exp":2}`)}.${'s1gnature'.repeat(4)}`

const SERVICE_JWT = fakeJwt('service_role')
const ANON_JWT = fakeJwt('anon')
const FAKE = {
  supabase: `sb_secret_${'Fake0'.repeat(6)}`,
  anthropicApi: `sk-ant-api03-${'Fake0x'.repeat(8)}`,
  anthropicOauth: `sk-ant-oat01-${'Fake0y'.repeat(8)}`,
  ghp: `ghp_${'A1'.repeat(18)}`,
  gho: `gho_${'B2'.repeat(18)}`,
  ghs: `ghs_${'C3'.repeat(18)}`,
  githubPat: `github_pat_${'D4_'.repeat(14)}`,
  openai: `sk-${'abc123'.repeat(5)}`,
  openaiProj: `sk-proj-${'def456'.repeat(6)}`,
  vercelP: `vcp_${'E5'.repeat(12)}`,
  vercelK: `vck_${'F6'.repeat(12)}`,
  linear: `lin_api_${'G7'.repeat(16)}`,
  aws: `AKIA${'FAKE'.repeat(4)}`,
}
const PEM = ['-----BEGIN RSA PRIVATE KEY-----', 'MIIFakeFakeFake', 'FakeFakeFake==', '-----END RSA PRIVATE KEY-----'].join('\n')

// The full tool union makes a literal `$.tool.call(...)` input too deep for tsc;
// the tests read results loosely anyway.
const callTool = (engine: Engine, input: Record<string, unknown>): Promise<ToolCallResult> =>
  (engine.tool.call as unknown as (input: unknown) => Promise<ToolCallResult>)(input)

const leaks = (text: string, ...values: string[]): string[] => values.filter(v => text.includes(v))

describe('redact', () => {
  test('a value that is not plain data throws, so callers fail closed', () => {
    expect(() => redactValue({ when: new Date(0) })).toThrow()
  })

  test('each pattern is replaced by its marker', () => {
    const cases: Array<[string, string]> = [
      [SERVICE_JWT, 'supabase-service-role-jwt'],
      [FAKE.supabase, 'supabase-secret'],
      [FAKE.anthropicApi, 'anthropic'],
      [FAKE.anthropicOauth, 'anthropic'],
      [FAKE.ghp, 'github'],
      [FAKE.gho, 'github'],
      [FAKE.ghs, 'github'],
      [FAKE.githubPat, 'github'],
      [FAKE.openai, 'openai'],
      [FAKE.openaiProj, 'openai'],
      [FAKE.vercelP, 'vercel'],
      [FAKE.vercelK, 'vercel'],
      [FAKE.linear, 'linear'],
      [FAKE.aws, 'aws-access-key'],
      [PEM, 'private-key'],
    ]
    for (const [value, kind] of cases) {
      const r = redact(`before ${value} after`)
      expect(r.text).toBe(`before [redacted:${kind}] after`)
      expect(r.kinds).toEqual([kind])
    }
  })

  test('a truncated private key block is redacted to the end', () => {
    const r = redact('key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktFake')
    expect(r.text).toBe('key:\n[redacted:private-key]')
  })

  test('.env lines lose their secret values and keep their names', () => {
    const env = [
      'SUPABASE_SERVICE_ROLE_KEY="not-a-jwt-but-secret"',
      'export DB_PASSWORD=hunter2hunter2',
      'GITHUB_TOKEN=plainfaketokenvalue',
      `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}`,
      'API_KEY=$OTHER_VAR',
      'FEATURE_TOKEN_CACHE=true',
      'NODE_ENV=production',
      'CANONICAL_TOKEN=fakefakefake',
    ].join('\n')
    const r = redact(env)
    expect(r.text.split('\n')).toEqual([
      'SUPABASE_SERVICE_ROLE_KEY=[redacted:env-secret]',
      'export DB_PASSWORD=[redacted:env-secret]',
      'GITHUB_TOKEN=[redacted:env-secret]',
      `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}`,
      'API_KEY=$OTHER_VAR',
      'FEATURE_TOKEN_CACHE=true',
      'NODE_ENV=production',
      'CANONICAL_TOKEN=[redacted:env-secret]',
    ])
    expect(r.kinds).toEqual(['env-secret', 'env-secret', 'env-secret', 'env-secret'])
  })

  test('a service_role JWT under a public name is still caught by its value', () => {
    const r = redact(`NEXT_PUBLIC_SUPABASE_ANON_KEY=${SERVICE_JWT}`)
    expect(r.text).toBe('NEXT_PUBLIC_SUPABASE_ANON_KEY=[redacted:supabase-service-role-jwt]')
  })

  test('JSON config keys are redacted', () => {
    const r = redact('{"apiKey": "fakeFAKEfake1234567890", "model": "x", "max_tokens": 100}')
    expect(r.text).toBe('{"apiKey": "[redacted:json-secret]", "model": "x", "max_tokens": 100}')
  })

  test('an anon JWT and ordinary output pass unchanged', () => {
    const plain = [
      `anon: ${ANON_JWT}`,
      'task-runner disk-usage sk-learn ghp_short AKIA',
      'const apiKey = process.env.API_KEY',
      '    api_key=os.environ["API_KEY"]',
      'total 20\ndrwxrwxr-x 5 c10 c10 4096 Oct 12 02:49 .',
    ].join('\n')
    const r = redact(plain)
    expect(r.text).toBe(plain)
    expect(r.kinds).toEqual([])
  })

  test('redactValue keeps structure and skips base64 payloads', () => {
    const value = { a: [FAKE.ghp, 1, true, null], file: { base64: FAKE.aws, type: 'image/png' } }
    const r = redactValue(value)
    expect(r.value).toEqual({ a: ['[redacted:github]', 1, true, null], file: { base64: FAKE.aws, type: 'image/png' } })
    expect(r.kinds).toEqual(['github'])
  })
})

describe('tool.call', () => {
  test('Bash stdout and stderr are redacted, with no ref', async ($, on) => {
    const toasts: string[] = []
    const statuses: string[] = []
    on('ui.toast', ($, e) => {
      toasts.push(e.text)
      return { value: undefined }
    })
    on('ui.status', ($, e) => {
      statuses.push(e.text ?? '')
      return { value: undefined }
    })
    on('tool.call', () => ({
      ref: 7,
      result: { stdout: `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_JWT}\n`, stderr: `warn ${FAKE.ghp}`, interrupted: false },
      text: `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_JWT}\nwarn ${FAKE.ghp}`,
    }))
    const r = await callTool($, { tool: 'Bash', command: 'cat .env' })
    expect(r.deny).toBeUndefined()
    expect(r.ref).toBeUndefined()
    const out = r.result as { stdout: string; stderr: string; interrupted: boolean }
    expect(out.stdout).toBe('SUPABASE_SERVICE_ROLE_KEY=[redacted:supabase-service-role-jwt]\n')
    expect(out.stderr).toBe('warn [redacted:github]')
    expect(out.interrupted).toBe(false)
    expect(toasts.length).toBe(1)
    expect(leaks(toasts.join('\n'), SERVICE_JWT, FAKE.ghp)).toEqual([])
    expect(toasts[0]).toContain('2 values')
    expect(statuses.length).toBe(1)
    expect(leaks(statuses.join('\n'), SERVICE_JWT, FAKE.ghp)).toEqual([])
  })

  test('Read content is redacted', async ($, on) => {
    on('tool.call', () => ({
      ref: 1,
      result: { type: 'text', file: { filePath: '/x/.env.local', content: PEM, numLines: 4, startLine: 1, totalLines: 4 } },
      text: PEM.split('\n').map((l, i) => `${i + 1}\t${l}`).join('\n'),
    }))
    const r = await callTool($, { tool: 'Read', file_path: '/x/.env.local' })
    const out = r.result as { file: { content: string; filePath: string } }
    expect(out.file.content).toBe('[redacted:private-key]')
    expect(out.file.filePath).toBe('/x/.env.local')
  })

  test('Read of a .env file: line-numbered text, redacted content, no deny', async ($, on) => {
    const content = 'NODE_ENV=production\nDB_PASSWORD=fakefakefake123\n'
    on('tool.call', () => ({
      ref: 8,
      result: { type: 'text', file: { filePath: '/x/.env', content, numLines: 2, startLine: 1, totalLines: 2 } },
      text: content.trimEnd().split('\n').map((l, i) => `     ${i + 1}\t${l}`).join('\n'),
    }))
    const r = await callTool($, { tool: 'Read', file_path: '/x/.env' })
    expect(r.deny).toBeUndefined()
    const out = r.result as { file: { content: string } }
    expect(out.file.content).toBe('NODE_ENV=production\nDB_PASSWORD=[redacted:env-secret]\n')
  })

  test('Grep content is redacted', async ($, on) => {
    on('tool.call', () => ({
      ref: 2,
      result: { mode: 'content', numFiles: 1, filenames: [], content: `cfg.json:3: "token": "${FAKE.linear}"`, numLines: 1 },
      text: `cfg.json:3: "token": "${FAKE.linear}"`,
    }))
    const r = await callTool($, { tool: 'Grep', pattern: 'token' })
    expect(leaks(JSON.stringify(r), FAKE.linear)).toEqual([])
  })

  test('ordinary output passes through untouched', async ($, on) => {
    const core = { ref: 3, result: { stdout: 'hello\n', stderr: '', interrupted: false }, text: 'hello' }
    on('tool.call', () => core)
    const r = await callTool($, { tool: 'Bash', command: 'echo hello' })
    expect(r.ref).toBe(3)
    expect(r.text).toBe('hello')
    expect(r.result).toEqual(core.result)
  })

  test('a tool of unknown shape is denied, with only the redacted text', async ($, on) => {
    on('tool.call', () => ({ ref: 4, result: { rows: [{ v: FAKE.supabase }] }, text: `[{"v":"${FAKE.supabase}"}]` }))
    const r = await callTool($, { tool: 'SomeOtherTool' })
    expect(r.deny).toContain('secret-redact')
    expect(r.deny).toContain('[redacted:supabase-secret]')
    expect(leaks(r.deny ?? '', FAKE.supabase)).toEqual([])
  })

  test('an errored result with a secret is denied', async ($, on) => {
    on('tool.call', () => ({ ref: 5, isError: true as const, result: `Exit 1\n${FAKE.openaiProj}`, text: `Exit 1\n${FAKE.openaiProj}` }))
    const r = await callTool($, { tool: 'Bash', command: 'false' })
    expect(r.deny).toContain('[redacted:openai]')
    expect(leaks(r.deny ?? '', FAKE.openaiProj)).toEqual([])
  })

  test('a failure in the hook withholds the result (fail closed)', async $ => {
    // No tool.call hook beneath: the kit's bottom throws, so the mod's
    // `await next(e)` throws and its .catch answers.
    const r = await callTool($, { tool: 'Bash', command: 'date' })
    expect(r.deny).toContain('fail closed')
  })
})

describe('session.append', () => {
  test('a pasted prompt is stored redacted', async ($, on) => {
    const session = mock.session(on)
    await $.session.append({
      message: { type: 'user', role: 'user', content: [{ type: 'text', text: `use ${FAKE.anthropicOauth} please` }] },
      door: 'prompt',
      origin: { kind: 'human' },
      uuid: '00000000-0000-4000-8000-000000000001',
    } as never)
    const rows = session.appended()
    const stored = JSON.stringify(rows.map(r => r.message))
    expect(stored).toContain('[redacted:anthropic]')
    expect(leaks(stored, FAKE.anthropicOauth)).toEqual([])
  })

  test('a model response text block is stored redacted', async ($, on) => {
    const session = mock.session(on)
    await $.session.append({
      message: { type: 'assistant', role: 'assistant', content: [{ type: 'text', text: `key is ${FAKE.vercelK}` }] },
      door: 'response',
      origin: { kind: 'model', model: 'claude-opus-5-5' },
      uuid: '00000000-0000-4000-8000-000000000002',
    } as never)
    const stored = JSON.stringify(session.appended().map(r => r.message))
    expect(stored).toContain('[redacted:vercel]')
    expect(leaks(stored, FAKE.vercelK)).toEqual([])
  })

  test('an ordinary row is stored unchanged', async ($, on) => {
    const session = mock.session(on)
    await $.session.append({
      message: { type: 'user', role: 'user', content: [{ type: 'text', text: 'hello there' }] },
      door: 'prompt',
      origin: { kind: 'human' },
      uuid: '00000000-0000-4000-8000-000000000003',
    } as never)
    expect(JSON.stringify(session.appended().map(r => r.message.content))).toBe('[[{"type":"text","text":"hello there"}]]')
  })
})
