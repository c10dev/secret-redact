import type { EngineInterface, Register } from 'claude-code'
import { type Kind, redact, redactValue, summarize } from './redact'

// Tools whose result is plain data the model's text is mapped from, so
// redacting every string in it redacts what the model reads. Any other tool
// with a secret in its output is withheld (deny) and the model gets only the
// redacted text.
const KNOWN_TOOLS: ReadonlySet<string> = new Set([
  'Bash',
  'Read',
  'Grep',
  'Glob',
  'Edit',
  'Write',
  'NotebookEdit',
  'WebFetch',
  'WebSearch',
  'Agent',
])

type Block = { type: string; [field: string]: unknown }

// Counts only, never values. Starts over on a reload.
let sessionTotal = 0

// The engine labels toasts and the status line with the plugin's name, so
// these texts carry none of their own. Deny texts do: the model reads those.
function notify($: EngineInterface, where: string, kinds: readonly Kind[]): void {
  sessionTotal += kinds.length
  $.ui.toast(`redacted ${summarize(kinds)} in ${where}`)
  $.ui.status(`${sessionTotal} redacted this session`)
}

export const register: Register = on => {
  // The prompt history (history.jsonl) records what this hook passes down, so a
  // typed prompt is redacted here as well as in its conversation row. A slash
  // command's line is left as typed: the engine applies no rewrite to it. A
  // prompt the person did not type (isMeta) takes no rewrite when it starts a
  // turn, so it passes as is; session.append redacts its stored row.
  on('prompt.submit', async ($, e, next) => {
    if (e.command !== undefined || e.isMeta === true) return next(e)
    const text = redact(e.text)
    const context = e.context?.map(c => redact(c))
    const kinds = [...text.kinds, ...(context?.flatMap(c => c.kinds) ?? [])]
    if (kinds.length === 0) return next(e)
    notify($, 'the prompt', kinds)
    return next(context === undefined ? { ...e, text: text.text } : { ...e, text: text.text, context: context.map(c => c.text) })
  }).catch(($, e, next) =>
    next.called ? next(e) : { drop: 'secret-redact: redaction failed, so this prompt was not sent (fail closed).' },
  )

  on('tool.call', async ($, e, next) => {
    const r = await next(e)

    if (r.deny !== undefined) {
      const d = redact(r.deny)
      if (d.kinds.length === 0) return r
      notify($, e.tool, d.kinds)
      return { deny: d.text }
    }

    const text = redact(r.text ?? '')
    const result = redactValue(r.result)
    const context = r.context?.map(c => redact(c))
    const contextKinds = context?.flatMap(c => c.kinds) ?? []
    if (text.kinds.length === 0 && result.kinds.length === 0 && contextKinds.length === 0) return r

    const kinds = [...(result.kinds.length >= text.kinds.length ? result.kinds : text.kinds), ...contextKinds]
    notify($, e.tool, kinds)

    // The model's text is mapped from `result`; when the text held a secret the
    // structured walk did not find, that mapping is not one this mod knows.
    const mappedFromResult = text.kinds.length === 0 || result.kinds.length > 0
    if (r.isError === true || !KNOWN_TOOLS.has(e.tool) || !mappedFromResult) {
      const why = r.isError === true ? 'an errored result' : `the ${e.tool} result`
      return {
        deny:
          `secret-redact: ${why} held ${summarize(kinds)}, so the original result is withheld. ` +
          `Only the redacted text follows.\n\n${text.text}`,
      }
    }

    const redactedContext = context?.map(c => c.text)
    return redactedContext === undefined ? { result: result.value } : { result: result.value, context: redactedContext }
  }).catch(() => ({
    deny: 'secret-redact: redaction failed, so this tool result is withheld (fail closed).',
  }))

  on('session.append', async ($, e, next) => {
    const kinds: Kind[] = []
    const scan = (s: string): string => {
      const r = redact(s)
      kinds.push(...r.kinds)
      return r.text
    }
    const content = e.message.content.map((block: Block): Block => {
      if (block.type === 'text' && typeof block.text === 'string') return { ...block, text: scan(block.text) }
      if (block.type === 'tool_result') {
        if (typeof block.content === 'string') return { ...block, content: scan(block.content) }
        if (Array.isArray(block.content)) {
          return {
            ...block,
            content: (block.content as Block[]).map(inner =>
              inner.type === 'text' && typeof inner.text === 'string' ? { ...inner, text: scan(inner.text) } : inner,
            ),
          }
        }
      }
      return block
    })
    if (kinds.length === 0) return next(e)
    notify($, `a conversation row (${e.door})`, kinds)
    return next({ ...e, message: { ...e.message, content } })
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    // The redaction itself failed. A row cannot be refused here, so swap any
    // block that even looks like it holds a secret for a notice and keep the rest.
    const SUSPECT = /eyJ|sb_secret_|sk-|gh[pousr]_|github_pat_|vc[pk]_|lin_(?:api|oauth)_|AKIA|ASIA|PRIVATE KEY|KEY=|SECRET|TOKEN|PASSWORD|PASSWD/i
    const withheld = '[secret-redact: redaction failed, so this block was not stored]'
    const content = e.message.content.map((block: Block): Block => {
      if (block.type === 'text' && typeof block.text === 'string' && SUSPECT.test(block.text)) {
        return { ...block, text: withheld }
      }
      if (block.type === 'tool_result' && SUSPECT.test(JSON.stringify(block.content ?? ''))) {
        return { ...block, content: withheld }
      }
      return block
    })
    return next({ ...e, message: { ...e.message, content } })
  })
}
