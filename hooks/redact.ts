// Pure redaction: no engine calls, so the tests import it directly.
// Every rule runs in time linear in its input (no two quantifiers that can
// trade the same characters, no rescans of a line), so a multi-megabyte tool
// output stays well inside a hook's budget; a test holds that to a time bound.
// A redacted value never leaves this module except as its `[redacted:<kind>]` marker.

export type Kind =
  | 'private-key'
  | 'anthropic'
  | 'supabase-secret'
  | 'github'
  | 'openai'
  | 'vercel'
  | 'linear'
  | 'aws-access-key'
  | 'supabase-service-role-jwt'
  | 'jwt-undecodable'
  | 'json-secret'
  | 'env-secret'

export type Redacted = { text: string; kinds: Kind[] }

const marker = (kind: Kind): string => `[redacted:${kind}]`

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/** Decodes base64url (padding optional) to text; undefined when it is not base64url. */
export const decodeBase64Url = (input: string): string | undefined => {
  const clean = input.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
  const bytes: number[] = []
  let buffer = 0
  let bits = 0
  for (const ch of clean) {
    const v = B64URL.indexOf(ch)
    if (v < 0) return undefined
    buffer = (buffer << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >> bits) & 0xff)
    }
  }
  const text = new TextDecoder().decode(new Uint8Array(bytes))
  return text.includes('\uFFFD') ? undefined : text
}

/** The JWT's verdict: a service_role key or an unreadable token is a secret; anything else (anon, user tokens) passes. */
const jwtKind = (token: string): Kind | undefined => {
  const payload = token.split('.')[1]
  const json = payload === undefined ? undefined : decodeBase64Url(payload)
  if (json === undefined) return 'jwt-undecodable'
  let claims: unknown
  try {
    claims = JSON.parse(json)
  } catch {
    return 'jwt-undecodable'
  }
  if (claims === null || typeof claims !== 'object') return 'jwt-undecodable'
  return (claims as { role?: unknown }).role === 'service_role' ? 'supabase-service-role-jwt' : undefined
}

// Names that are public by design: Next.js ships NEXT_PUBLIC_* to the browser,
// Supabase anon/publishable keys are public. A secret value under such a name
// is still caught by the value patterns above (a service_role JWT, sb_secret_).
const PUBLIC_NAME = /^NEXT_PUBLIC_|(?:^|[_.-])ANON(?:[_.-]|$)|PUBLISHABLE|PUBLIC_KEY/i

// Values that point elsewhere instead of holding the secret.
const REFERENCE_VALUE = /^(?:\$|process\.env|os\.environ|os\.getenv|getenv\(|env\(|ENV\[|<|\[redacted:)/

const TRIVIAL_VALUE = /^(?:|true|false|null|none|yes|no|on|off|0|1)$/i

const unquote = (value: string): string => {
  const v = value.trim()
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) return v.slice(1, -1)
  return v
}

// A name is a secret's when one of its words ends in a keyword, plural or
// numbered: DB_PASSWORD, PASSWORD_DB, API_KEY_2, SECRETS, APIKEY, apiKey.
// TOKENS stays out (MAX_TOKENS is a count), and so do words that only end in
// KEY (MONKEY, TURKEY) or hold a keyword inside (KEYBOARD, TOKENIZER).
const SECRET_WORD = /(?:KEYS?|SECRETS?|TOKEN|PASSWORDS?|PASSWDS?)\d*$/i
const NOT_A_KEY = /^(?:MON|DON|TUR|HOC|JOC|WHIS|LAC|HOT)KEYS?\d*$/i

/** The words of a name: DB_PASSWORD, db-password, db.password and dbPassword all give [db, password]. */
const words = (name: string): string[] => name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[ _.-]+/)

const isSecretName = (name: string): boolean => words(name).some(w => SECRET_WORD.test(w) && !NOT_A_KEY.test(w))

// The env rule's candidates: an UPPER_CASE name and `=` (not `==`, `=>` or
// `=~`), at a line start or after whitespace or one of : + - " ' { , ; ? &.
// That covers .env, `export`, `ENV` and `declare -x` lines, Grep's `N:` and
// `file:N:` prefixes, `cat -n`, diff `+`/`-` lines, compose `- NAME=` items,
// docker inspect's `"NAME=value"` and URL queries. None of those characters
// can be part of a name, so each run of name characters is tried once.
const ENV_ASSIGNMENT = /(?<=(^|[\s:+\-"'{,;?&]))([A-Z][A-Z0-9_]*)([ \t]*)=(?![=>~])([ \t]*)/gm
const LINE_END = /[\r\n]/g
// Enough of a value to tell a reference or a trivial value from a secret.
const HEAD = 64
// With spaces around `=` the line is more likely code than .env: there a plain
// number or a value that opens a list, dict or tuple is not a secret
// (`MAX_TOKENS = 4096`, `API_KEYS = [`).
const NUMBER = /^[-+]?\d[\d_]*(?:\.\d+)?$/
const OPENS_LITERAL = /^[[{(]/

/**
 * The env rule. It scans rather than replaces so that a name it lets pass
 * (`NODE_ENV=production DB_PASSWORD=x`) does not take the rest of its line with it.
 * The value runs to the end of the line, or to the closing quote of a quoted
 * `"NAME=value"`. Each line's end and each quote is searched for once.
 */
const redactEnv = (text: string, kinds: Kind[]): string => {
  const parts: string[] = []
  let copied = 0
  let lineEnd = -1
  ENV_ASSIGNMENT.lastIndex = 0
  for (let m = ENV_ASSIGNMENT.exec(text); m !== null; m = ENV_ASSIGNMENT.exec(text)) {
    const [, lead = '', name = '', spaceBefore = '', spaceAfter = ''] = m
    if (!isSecretName(name) || PUBLIC_NAME.test(name)) continue
    const start = ENV_ASSIGNMENT.lastIndex
    if (lineEnd < start) {
      LINE_END.lastIndex = start
      lineEnd = LINE_END.exec(text)?.index ?? text.length
    }
    let end = lineEnd
    if (lead === '"' || lead === "'") {
      const close = text.indexOf(lead, start)
      if (close !== -1 && close < lineEnd) end = close
    }
    const head = text.slice(start, Math.min(end, start + HEAD))
    const whole = end - start <= HEAD ? unquote(head) : undefined
    const spaced = spaceBefore !== '' || spaceAfter !== ''
    if (REFERENCE_VALUE.test(head.replace(/^["']/, ''))) continue
    if (whole !== undefined && (TRIVIAL_VALUE.test(whole) || (spaced && NUMBER.test(whole)))) continue
    if (spaced && OPENS_LITERAL.test(head)) continue
    parts.push(text.slice(copied, start), marker('env-secret'))
    kinds.push('env-secret')
    copied = end
    ENV_ASSIGNMENT.lastIndex = end
  }
  if (parts.length === 0) return text
  parts.push(text.slice(copied))
  return parts.join('')
}

type Rule =
  | { kind: Kind; pattern: RegExp; replace?: (match: string, ...groups: string[]) => string | undefined }
  | { kind: Kind; apply: (text: string, kinds: Kind[]) => string }

// Order matters: a PEM block before the tokens inside it, sk-ant- before sk-,
// value patterns before the name-based rules (which skip already-redacted values).
const RULES: Rule[] = [
  {
    kind: 'private-key',
    // A truncated block (no END line) is redacted to the end of the text.
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
  },
  { kind: 'anthropic', pattern: /(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{16,}/g },
  { kind: 'supabase-secret', pattern: /(?<![A-Za-z0-9_])sb_secret_[A-Za-z0-9_-]{10,}/g },
  { kind: 'github', pattern: /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/g },
  {
    kind: 'openai',
    // Requires a digit and a letter so identifiers like sk-learn-style names pass.
    pattern: /(?<![A-Za-z0-9_-])sk-(?!ant-)(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{20,}/g,
  },
  { kind: 'vercel', pattern: /(?<![A-Za-z0-9_])vc[pk]_[A-Za-z0-9_-]{20,}/g },
  { kind: 'linear', pattern: /(?<![A-Za-z0-9_])lin_(?:api|oauth)_[A-Za-z0-9_-]{20,}/g },
  { kind: 'aws-access-key', pattern: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g },
  {
    kind: 'supabase-service-role-jwt',
    pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    replace: match => {
      const kind = jwtKind(match)
      return kind === undefined ? undefined : marker(kind)
    },
  },
  {
    kind: 'json-secret',
    // "apiKey": "<16+ chars, no spaces>": JSON config files. One quantifier over
    // the name keeps it linear; the keyword is checked on the name it found.
    pattern: /"([A-Za-z0-9_.-]{1,128})"(\s*:\s*)"([^"\\\s]{16,})"/g,
    replace: (match, name = '', sep = '', value = '') =>
      !isSecretName(name) || PUBLIC_NAME.test(name) || REFERENCE_VALUE.test(value)
        ? undefined
        : `"${name}"${sep}"${marker('json-secret')}"`,
  },
  // .env, `env`, `export` and `NAME = value` lines, wherever the name starts on a line.
  { kind: 'env-secret', apply: redactEnv },
]

/** Redacts every secret the rules know in `text`; `kinds` has one entry per value redacted. */
export const redact = (text: string): Redacted => {
  const kinds: Kind[] = []
  let out = text
  for (const rule of RULES) {
    if ('apply' in rule) {
      out = rule.apply(out, kinds)
      continue
    }
    rule.pattern.lastIndex = 0
    out = out.replace(rule.pattern, (match: string, ...rest: unknown[]) => {
      const groups = rest.filter((g): g is string => typeof g === 'string')
      if (rule.replace === undefined) {
        kinds.push(rule.kind)
        return marker(rule.kind)
      }
      const replaced = rule.replace(match, ...groups)
      if (replaced === undefined) return match
      // A JWT's marker names its own kind.
      const kind = /\[redacted:([a-z-]+)\]/.exec(replaced)?.[1] as Kind | undefined
      kinds.push(kind ?? rule.kind)
      return replaced
    })
  }
  return { text: out, kinds }
}

/** True when `text` holds a secret the rules know. */
export const hasSecret = (text: string): boolean => redact(text).kinds.length > 0

// Binary payloads (Read's image/pdf/page base64, image blocks' data) are not
// text: scanning them only finds noise, and rewriting them breaks the image.
const isBinaryField = (key: string, parent: Record<string, unknown>): boolean =>
  key === 'base64' || (key === 'data' && ('media_type' in parent || 'mediaType' in parent))

/**
 * Redacts every string inside a JSON-shaped value, keeping its structure
 * exactly (same keys, same array lengths, same non-string leaves).
 * Throws on anything that is not plain data, so a caller fails closed.
 */
export const redactValue = (value: unknown): { value: unknown; kinds: Kind[] } => {
  const kinds: Kind[] = []
  const walk = (v: unknown, depth: number): unknown => {
    if (depth > 64) throw new Error('secret-redact: value nested too deeply')
    if (typeof v === 'string') {
      const r = redact(v)
      kinds.push(...r.kinds)
      return r.text
    }
    if (v === null || v === undefined || typeof v === 'number' || typeof v === 'boolean') return v
    if (Array.isArray(v)) return v.map(item => walk(item, depth + 1))
    if (typeof v === 'object') {
      // Realm-safe plain-object check: a Date, Map or class instance throws.
      if (Object.prototype.toString.call(v) !== '[object Object]') throw new Error('secret-redact: not plain data')
      const src = v as Record<string, unknown>
      const out: Record<string, unknown> = {}
      for (const [k, item] of Object.entries(src)) out[k] = isBinaryField(k, src) ? item : walk(item, depth + 1)
      return out
    }
    throw new Error(`secret-redact: unsupported ${typeof v}`)
  }
  const out = walk(value, 0)
  return { value: out, kinds }
}

/** A short summary of what was redacted, with no value in it: `2 values (github, env-secret)`. */
export const summarize = (kinds: readonly Kind[]): string =>
  `${kinds.length} ${kinds.length === 1 ? 'value' : 'values'} (${[...new Set(kinds)].join(', ')})`
