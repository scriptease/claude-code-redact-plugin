// redact: keeps secrets and personal data out of the model's context.
//
// The user hands a secret over with a `redact NAME=value` prompt. The prompt is
// dropped before the model sees it and the value is kept in this module's Map,
// which lives exactly as long as the session (a reload or a new session starts
// empty; nothing is written to $.store or disk).
//
// From then on:
//   prompt.submit  known values (and, with autoDetect, e-mails, IBANs, card
//                  numbers, JWTs, API keys, PEM keys) become REDACTED_<NAME>
//                  placeholders before the text reaches the model.
//   tool.call      placeholders in the tool's arguments are swapped back to the
//                  real values before the tool runs, and real values in the
//                  tool's result are swapped to placeholders before the model
//                  reads it.
import type { Register, ToolCallInput } from 'claude-code'

const PREFIX = 'REDACTED_'
const PLACEHOLDER = /REDACTED_[A-Z0-9_]+/g
const MIN_LENGTH = 4
const COMMAND = /^\s*redact\b/i

type Entry = { placeholder: string; value: string }

// placeholder -> value; per session by construction (module state).
const secrets = new Map<string, string>()
// Cached view sorted by value length, longest first, so a value that contains
// another value is replaced whole.
let entries: Entry[] = []

function remember(name: string, value: string): string {
  const placeholder = PREFIX + name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')
  for (const [key, existing] of secrets) if (existing === value) return key
  secrets.set(placeholder, value)
  entries = [...secrets].map(([placeholder, value]) => ({ placeholder, value })).sort((a, b) => b.value.length - a.value.length)
  return placeholder
}

function forget(placeholder?: string) {
  if (placeholder) secrets.delete(placeholder)
  else secrets.clear()
  entries = entries.filter(x => secrets.has(x.placeholder))
}

// --- auto detection --------------------------------------------------------

type Detector = { kind: string; pattern: RegExp; accept?: (match: string) => boolean }

function luhn(digits: string): boolean {
  let sum = 0
  let double = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (double) { d *= 2; if (d > 9) d -= 9 }
    sum += d
    double = !double
  }
  return sum % 10 === 0
}

const DETECTORS: Detector[] = [
  { kind: 'PEM_KEY', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'JWT', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: 'API_KEY', pattern: /\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b/g },
  { kind: 'BEARER', pattern: /(?<=\bBearer\s+)[A-Za-z0-9._~+/=-]{16,}/g },
  { kind: 'EMAIL', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { kind: 'IBAN', pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },
  { kind: 'CARD', pattern: /\b(?:\d[ -]?){12,18}\d\b/g, accept: m => luhn(m.replace(/[ -]/g, '')) },
]

const counters = new Map<string, number>()

function detect(text: string): string {
  for (const { kind, pattern, accept } of DETECTORS) {
    text = text.replace(pattern, match => {
      if (match.startsWith(PREFIX) || (accept && !accept(match))) return match
      for (const e of entries) if (e.value === match) return e.placeholder
      const n = (counters.get(kind) ?? 0) + 1
      counters.set(kind, n)
      return remember(`${kind}_${n}`, match)
    })
  }
  return text
}

// --- replacement -----------------------------------------------------------

function conceal(text: string, autoDetect: boolean): string {
  for (const { placeholder, value } of entries) text = text.split(value).join(placeholder)
  return autoDetect ? detect(text) : text
}

function reveal(text: string): string {
  return text.replace(PLACEHOLDER, p => secrets.get(p) ?? p)
}

// Applies `fn` to every string leaf; returns the input object when nothing changed.
function mapStrings<T>(value: T, fn: (s: string) => string): T {
  if (typeof value === 'string') return fn(value) as T
  if (Array.isArray(value)) {
    let changed = false
    const out = value.map(v => { const r = mapStrings(v, fn); if (r !== v) changed = true; return r })
    return (changed ? out : value) as T
  }
  if (value && typeof value === 'object') {
    let changed = false
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) { const r = mapStrings(v, fn); if (r !== v) changed = true; out[k] = r }
    return (changed ? out : value) as T
  }
  return value
}

// --- the `redact ...` command ----------------------------------------------

function command(text: string): string {
  const args = text.replace(COMMAND, '').trim()
  if (args === '' || args === 'list') {
    if (secrets.size === 0) return 'redact: nothing stored. Usage: redact NAME=value | redact list | redact forget NAME | redact clear'
    return 'redact: ' + [...secrets.keys()].join(', ')
  }
  if (args === 'clear') { forget(); return 'redact: cleared' }
  const single = args.match(/^forget\s+(\S+)$/i)
  if (single) {
    const key = single[1].toUpperCase().startsWith(PREFIX) ? single[1].toUpperCase() : PREFIX + single[1].toUpperCase()
    if (!secrets.has(key)) return `redact: ${key} not stored`
    forget(key)
    return `redact: forgot ${key}`
  }
  const stored: string[] = []
  const rejected: string[] = []
  for (const line of args.split('\n')) {
    const m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*[=:]\s*(.+?)\s*$/)
    if (!m) { if (line.trim()) rejected.push(line.trim()); continue }
    const value = m[2].replace(/^(["'])(.*)\1$/, '$2')
    if (value.length < MIN_LENGTH) { rejected.push(`${m[1]} (value shorter than ${MIN_LENGTH})`); continue }
    stored.push(remember(m[1], value))
  }
  const parts = []
  if (stored.length) parts.push(`stored ${stored.join(', ')} (use the placeholder verbatim in prompts)`)
  if (rejected.length) parts.push(`ignored: ${rejected.join('; ')}`)
  return 'redact: ' + (parts.join('. ') || 'nothing to store. Usage: redact NAME=value')
}

const MODEL_NOTE =
  'Tokens of the form REDACTED_<NAME> are placeholders for secrets or personal data the user gave the session. ' +
  'Never guess or reconstruct their values. Use the placeholder verbatim wherever the real value belongs ' +
  '(commands, file contents, request bodies); it is substituted with the real value before the tool executes, ' +
  'and real values in tool output are replaced with the placeholder again.'

export const register: Register = (on, options) => {
  const autoDetect = options.autoDetect !== false

  on('prompt.submit', async ($, e, next) => {
    if (COMMAND.test(e.text)) {
      const reply = command(e.text)
      $.ui.toast(reply, { timeoutMs: 8000 })
      return { drop: reply }
    }
    const text = conceal(e.text, autoDetect)
    if (text === e.text && secrets.size === 0) return next(e)
    if (text !== e.text) $.ui.toast('redact: placeholders substituted in prompt')
    const r = await next({ ...e, text })
    if (r.drop !== undefined) return r
    return { ...r, context: [...(r.context ?? []), MODEL_NOTE] }
  })

  on('tool.call', async ($, e, next) => {
    const revealed = secrets.size ? mapStrings(e, reveal) : e
    const r = await next(revealed as ToolCallInput)
    if (r.deny !== undefined) return r
    if (r.isError) {
      const text = r.text === undefined ? undefined : conceal(r.text, autoDetect)
      return text === undefined || text === r.text ? r : { deny: text }
    }
    const result = mapStrings(r.result, s => conceal(s, autoDetect))
    if (result === r.result) return r
    return { result, context: r.context }
  })
}
