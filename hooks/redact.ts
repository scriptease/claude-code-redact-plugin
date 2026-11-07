// redact: keeps secrets and personal data out of the model's context.
//
// The user hands a secret over with a `redact NAME=value` prompt. The prompt is
// dropped before the model sees it and the value is kept for the session.
//
// From then on:
//   prompt.submit  known values (and, with autoDetect, e-mails, IBANs, card
//                  numbers, JWTs, API keys, PEM keys, credential headers and
//                  key=value credentials) become REDACTED_<NAME> placeholders
//                  before the text reaches the model.
//   tool.call      placeholders in the tool's arguments are swapped back to the
//                  real values before the tool runs, and real values in the
//                  tool's result are swapped to placeholders before the model
//                  reads it.
//
// The secrets survive a restart or a `--resume` of the session: they are kept in
// <session folder>/redact.enc next to the transcript, encrypted by the system
// openssl (AES-256-CBC, PBKDF2) with one key from the macOS Keychain, the session
// id inside and checked on load. The mod runtime's crypto.subtle has only digest,
// hence openssl. A fork, `/branch` or `/clear` starts a new session id and
// therefore starts empty.
import type { EngineInterface, Register, ToolCallInput } from 'claude-code'

const PREFIX = 'REDACTED_'
const PLACEHOLDER = /REDACTED_[A-Z0-9_]+/g
const MIN_LENGTH = 4
const COMMAND = /^\s*redact\b/i
const FILE = 'redact.enc'
const MAX_FILE = 4 * 1024 * 1024 // $.fs.read and $.process.run output stop here
const KEYCHAIN = ['-s', 'claude-code-redact', '-a', 'aes-key']
// Tools whose input becomes another model's prompt: placeholders are passed on
// as they are. A subagent shares this process and resolves them in its own tool
// calls; another session cannot, by design.
const MODEL_FACING = /^(?:Agent|Task|Skill|SubagentHandback|SendMessage|mcp__t3-code__(?:delegate_task|t3_thread_send|t3_thread_launch|create_threads|schedule_task))$/
const OPENSSL = ['/usr/bin/openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-a', '-A', '-pass', 'env:REDACT_KEY']

type Session = {
  id: string
  dir: string | undefined // <config>/projects/<slug>/<id>; found once the transcript exists
  isPersistent: boolean // false when the Keychain could not open an existing file
  secrets: Map<string, string> // placeholder -> value
  byValue: Map<string, string> // value -> placeholder
  counters: Map<string, number> // auto-detected kind -> last number, never reused
  matcher: RegExp | undefined // every placeholder and value, longest first; rebuilt after a change
  warnedFor: string | undefined // detectorsVersion() the history warning was shown for; kept in redact.enc
  isDirty: boolean
}

function emptySession(id: string): Session {
  return { id, dir: undefined, isPersistent: true, secrets: new Map(), byValue: new Map(), counters: new Map(), matcher: undefined, warnedFor: undefined, isDirty: false }
}

function placeholderOf(name: string): string {
  return PREFIX + name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')
}

function remember(s: Session, name: string, value: string): string {
  const existing = s.byValue.get(value)
  if (existing) return existing
  const placeholder = placeholderOf(name)
  const old = s.secrets.get(placeholder)
  if (old !== undefined) s.byValue.delete(old)
  s.secrets.set(placeholder, value)
  s.byValue.set(value, placeholder)
  s.matcher = undefined
  s.isDirty = true
  return placeholder
}

function forget(s: Session, placeholder?: string) {
  const targets = placeholder ? [placeholder] : [...s.secrets.keys()]
  for (const p of targets) {
    const value = s.secrets.get(p)
    if (value !== undefined) s.byValue.delete(value)
    s.secrets.delete(p)
  }
  s.matcher = undefined
  s.isDirty = true
}

// --- persistence -------------------------------------------------------------

let key: string | undefined

async function readKey($: EngineInterface): Promise<string | undefined> {
  const r = await $.process.run(['security', 'find-generic-password', ...KEYCHAIN, '-w'])
  return r.exitCode === 0 && r.stdout.trim() ? r.stdout.trim() : undefined
}

// One 256-bit key for all sessions, created on first use. It goes to `security`
// over stdin and to openssl through its environment, never through argv.
async function keyOf($: EngineInterface): Promise<string> {
  if (key) return key
  let hex = await readKey($)
  if (!hex) {
    const fresh = [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('')
    await $.process.run(['security', '-i'], { stdin: `add-generic-password ${KEYCHAIN.join(' ')} -w ${fresh}\n` })
    hex = await readKey($) // another session may have created it first
  }
  if (!hex || !/^[0-9a-f]{64}$/.test(hex)) throw new Error('no usable key in the Keychain (claude-code-redact / aes-key)')
  key = hex
  return key
}

async function openssl($: EngineInterface, args: string[], input: string): Promise<string> {
  const r = await $.process.run([...OPENSSL, ...args], { stdin: input, env: { REDACT_KEY: await keyOf($) } })
  if (r.exitCode !== 0) throw new Error(`openssl failed (${r.exitCode})`)
  if (r.isStdoutTruncated) throw new Error(`${FILE} exceeds ${MAX_FILE} bytes`)
  return r.stdout
}

// Rejects when the transcript exists in more than one project folder: the
// session's secret file would be ambiguous.
async function findDir($: EngineInterface, id: string): Promise<string | undefined> {
  const config = (await $.env.get('CLAUDE_CONFIG_DIR')) ?? `${await $.env.get('HOME')}/.claude`
  const root = `${config}/projects`
  const found: string[] = []
  for (const d of await $.fs.list(root)) {
    if (d.kind === 'dir' && (await $.fs.exists(`${root}/${d.name}/${id}.jsonl`))) found.push(`${root}/${d.name}/${id}`)
  }
  if (found.length > 1) throw new Error(`session ${id} found in ${found.length} project folders: ${found.join(', ')}`)
  return found[0]
}

async function load($: EngineInterface, id: string): Promise<Session> {
  const s = emptySession(id)
  try {
    s.dir = await findDir($, id)
    if (!s.dir || !(await $.fs.exists(`${s.dir}/${FILE}`))) return s
    await keyOf($)
  } catch (err) {
    s.isPersistent = false // keep any file untouched; this session runs from memory only
    $.ui.toast(`redact: ${(err as Error).message}; secrets of this session are not loaded and not saved`, { timeoutMs: 10000 })
    return s
  }
  const path = `${s.dir}/${FILE}`
  try {
    const blob = JSON.parse(await openssl($, ['-d'], await $.fs.read(path))) as { id: string; secrets: Record<string, string>; counters: Record<string, number>; warnedFor?: string }
    if (blob.id !== id) throw new Error(`belongs to session ${blob.id}`)
    for (const [placeholder, value] of Object.entries(blob.secrets)) {
      s.secrets.set(placeholder, value)
      s.byValue.set(value, placeholder)
    }
    for (const [kind, n] of Object.entries(blob.counters)) s.counters.set(kind, n)
    s.warnedFor = blob.warnedFor
  } catch (err) {
    const aside = `${path}.corrupt-${Date.now()}`
    const isMoved = (await $.process.run(['mv', path, aside])).exitCode === 0
    if (!isMoved) s.isPersistent = false // never overwrite a file that could still be recovered
    const where = isMoved ? `moved to ${aside}` : 'left in place (move failed); this session runs from memory only'
    $.ui.toast(`redact: ${FILE} unreadable (${(err as Error).message}), ${where}; starting empty`, { timeoutMs: 10000 })
  }
  return s
}

// Writes the whole state to a temp file and renames it over redact.enc, so a
// kill mid-write leaves the previous file intact.
async function save($: EngineInterface, s: Session): Promise<void> {
  if (!s.isDirty || !s.isPersistent) return
  if (!s.dir) {
    try {
      s.dir = await findDir($, s.id)
    } catch (err) {
      s.isPersistent = false
      throw err
    }
  }
  if (!s.dir) return // new session without a transcript yet; the next hook retries
  s.isDirty = false
  try {
    const blob = JSON.stringify({ id: s.id, secrets: Object.fromEntries(s.secrets), counters: Object.fromEntries(s.counters), warnedFor: s.warnedFor })
    const text = await openssl($, ['-salt'], blob)
    const path = `${s.dir}/${FILE}`
    const tmp = `${path}.tmp-${crypto.randomUUID()}`
    await $.fs.write(tmp, text)
    const r = await $.process.run(['mv', '-f', tmp, path])
    if (r.exitCode !== 0) throw new Error(`mv failed: ${r.stderr.trim()}`)
  } catch (err) {
    s.isDirty = true
    throw err
  }
}

// --- session tracking ----------------------------------------------------------

let activeId: string | undefined
let active: Promise<Session> | undefined
let writing: Promise<void> = Promise.resolve()

async function current($: EngineInterface, autoDetect: boolean): Promise<Session> {
  const id = await $.session.id()
  if (id !== activeId || !active) {
    activeId = id
    const loading = load($, id).then(s => (autoDetect ? warnAboutHistory($, s) : s))
    active = loading
    loading.catch(() => { if (active === loading) active = undefined }) // retry on the next hook
  }
  return active
}

// Values that entered the transcript before redact was active stay readable to
// the model. Says so once per session and detector version, so a change to the
// detectors scans the history again.
async function warnAboutHistory($: EngineInterface, s: Session): Promise<Session> {
  const version = await detectorsVersion()
  if (s.warnedFor === version) return s
  const found = new Map<string, string>() // value -> kind
  try {
    mapStrings(await $.session.messages({ as: 'api' }), text => { suspects(text, found); return text })
  } catch {
    return s // best effort: masking must not depend on reading the history
  }
  if (found.size === 0) return s
  const kinds = [...new Set(found.values())].join(', ')
  $.ui.toast(
    `redact: this session's history already holds ${found.size} secret-looking value(s) from before redact was active (${kinds}). ` +
      'They stay readable to the model; rotate them or start a new session.',
    { timeoutMs: 15000 },
  )
  s.warnedFor = version
  s.isDirty = true
  return s
}

// Writes run one after another; each writes the newest full state.
async function persist($: EngineInterface, s: Session): Promise<void> {
  writing = writing.then(() => save($, s)).catch(err => $.ui.toast(`redact: could not save secrets: ${(err as Error).message}`, { timeoutMs: 10000 }))
  return writing
}

// --- auto detection --------------------------------------------------------

// `value` (or `dq`/`sq` for a quoted value) names the part to replace; without
// it the whole match is replaced. `name`, when matched, names the placeholder
// (REDACTED_<NAME>_<n>). Every repetition is bounded or anchored on a literal so
// matching stays linear in the text length.
type Detector = { kind: string; pattern: RegExp; accept?: (value: string, name?: string) => boolean }

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

// Values after a credential name that are references or code, not secrets.
const NOT_A_SECRET = /^(?:[%{<]|\$\{|\$[A-Za-z_][A-Za-z0-9_]*$|REDACTED_|process\.env|os\.environ|(?:null|true|false|undefined|none|string|number|boolean)$)/i
// A short number is a count (`max_tokens: 4096`) unless the name says password or secret.
const COUNT = /^\d{1,7}$/

function isCredential(value: string, name = ''): boolean {
  return !NOT_A_SECRET.test(value) && (!COUNT.test(value) || /passw|secret/i.test(name))
}

const DETECTORS: Detector[] = [
  { kind: 'PEM_KEY', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'JWT', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: 'API_KEY', pattern: /\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|ATATT3[A-Za-z0-9_=-]{25,})\b/g },
  // Credential headers, by header name: curl -H, HTTP dumps, trace entries, JSON
  // header maps. The auth scheme stays readable; the value runs to the end of
  // the line, a quote, a comma or a closing bracket.
  {
    kind: 'HEADER',
    pattern: /(?<pre>\b(?<name>(?:proxy-)?authorization|x-api-key|api-key|x-auth-token|x-access-token|cookie|set-cookie)["']?\s*[:=]\s*\[?["']?(?:(?:bearer|basic|token|digest|negotiate)\s+)?)(?<value>[^\s"'\]][^"'\r\n,}\]]*)/gim,
    accept: isCredential,
  },
  // key=value / key: value where the key names a credential: env files, YAML,
  // JSON, properties, URL query strings. A quoted value runs to its closing
  // quote; an unquoted one is one token.
  {
    kind: 'KEYED',
    pattern: /(?<pre>(?<![A-Za-z0-9])(?<name>[A-Za-z0-9_.-]{0,40}(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?)[A-Za-z0-9_.-]{0,40})["']?\s*[:=]\s*)(?:"(?<dq>(?:[^"\\\r\n]|\\.)*)"|'(?<sq>(?:[^'\\\r\n]|\\.)*)'|["']?(?<value>[^\s"'`,;&}\]]+))/gi,
    accept: isCredential,
  },
  { kind: 'BEARER', pattern: /(?<pre>\bBearer\s+)(?<value>[A-Za-z0-9._~+/=-]{16,})/g },
  { kind: 'EMAIL', pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g },
  { kind: 'IBAN', pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },
  { kind: 'CARD', pattern: /\b(?:\d[ -]?){12,18}\d\b/g, accept: m => luhn(m.replace(/[ -]/g, '')) },
]

let version: string | undefined

// A hash of everything that decides what is detected.
async function detectorsVersion(): Promise<string> {
  if (version) return version
  const source = [MIN_LENGTH, ...DETECTORS.map(d => `${d.kind} ${d.pattern.source} ${d.pattern.flags} ${d.accept ?? ''}`), NOT_A_SECRET.source, COUNT.source, luhn].join('\n')
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(source)))
  version = [...digest.slice(0, 8)].map(b => b.toString(16).padStart(2, '0')).join('')
  return version
}

function mask(s: Session, kind: string, value: string): string {
  const existing = s.byValue.get(value)
  if (existing) return existing
  let n = s.counters.get(kind) ?? 0
  do n++
  while (s.secrets.has(placeholderOf(`${kind}_${n}`))) // `redact EMAIL_1=...` keeps its name
  s.counters.set(kind, n)
  return remember(s, `${kind}_${n}`, value)
}

type Groups = Record<string, string | undefined> | undefined

// The secret part of a match: the quoted or token value when the pattern names
// one, else the whole match; trailing whitespace is not part of it.
function valueOf(match: string, groups: Groups): string {
  return (groups?.dq ?? groups?.sq ?? groups?.value ?? match).trimEnd()
}

function isCandidate(value: string, accept: Detector['accept'], name?: string): boolean {
  return value.length >= MIN_LENGTH && !value.includes(PREFIX) && (!accept || accept(value, name))
}

function kindOf(kind: string, groups: Groups): string {
  return groups?.name ? placeholderOf(groups.name).slice(PREFIX.length) : kind
}

// Collects what the detectors would mask, without masking it.
function suspects(text: string, found: Map<string, string>) {
  for (const { kind, pattern, accept } of DETECTORS) {
    for (const m of text.matchAll(pattern)) {
      const value = valueOf(m[0], m.groups)
      if (isCandidate(value, accept, m.groups?.name)) found.set(value, kindOf(kind, m.groups))
    }
  }
}

function detect(s: Session, text: string): string {
  for (const { kind, pattern, accept } of DETECTORS) {
    text = text.replace(pattern, (match: string, ...rest: unknown[]) => {
      const last = rest.at(-1)
      const groups = (typeof last === 'object' ? last : undefined) as Groups
      const value = valueOf(match, groups)
      if (!isCandidate(value, accept, groups?.name)) return match
      const placeholder = mask(s, kindOf(kind, groups), value)
      if (value === match) return placeholder
      const pre = groups?.pre ?? ''
      return pre + match.slice(pre.length).replace(value, () => placeholder)
    })
  }
  return text
}

// --- replacement -----------------------------------------------------------

// One pass over the text, so a placeholder it inserts is never rescanned. The
// alternatives are this session's placeholders and values, longest first: a
// placeholder is kept whole (`EMAIL` inside REDACTED_EMAIL_1 stays), a value is
// replaced, and a value containing another is replaced whole.
function replaceKnown(s: Session, text: string): string {
  if (s.secrets.size === 0) return text
  s.matcher ??= new RegExp(
    [...s.secrets.keys(), ...s.secrets.values()]
      .sort((a, b) => b.length - a.length)
      .map(x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('|'),
    'g',
  )
  return text.replace(s.matcher, m => s.byValue.get(m) ?? m)
}

// Known values first, then detection; a value detected in this text is
// replaced again wherever else it occurs in it.
function conceal(s: Session, text: string, autoDetect: boolean): string {
  text = replaceKnown(s, text)
  if (!autoDetect) return text
  const before = s.secrets.size
  text = detect(s, text)
  return s.secrets.size === before ? text : replaceKnown(s, text)
}

// conceal over every string of a value (keys included), with a second pass
// when a later string revealed a value an earlier one also holds.
function concealAll<T>(s: Session, value: T, autoDetect: boolean): T {
  const before = s.secrets.size
  const out = mapStrings(value, x => conceal(s, x, autoDetect))
  return s.secrets.size === before ? out : mapStrings(out, x => replaceKnown(s, x))
}

function reveal(s: Session, text: string): string {
  return text.replace(PLACEHOLDER, p => s.secrets.get(p) ?? p)
}

// Applies `fn` to every string leaf and object key; returns the input object when nothing changed.
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
    for (const [k, v] of Object.entries(value)) {
      const key = fn(k)
      const r = mapStrings(v, fn)
      if (r !== v || key !== k) changed = true
      out[key] = r
    }
    return (changed ? out : value) as T
  }
  return value
}

// --- the `redact ...` command ----------------------------------------------

function command(s: Session, text: string): string {
  const args = text.replace(COMMAND, '').trim()
  if (args === '' || args === 'list') {
    if (s.secrets.size === 0) return 'redact: nothing stored. Usage: redact NAME=value | redact list | redact forget NAME | redact clear'
    return 'redact: ' + [...s.secrets.keys()].join(', ')
  }
  if (args === 'clear') { forget(s); return 'redact: cleared' }
  const single = args.match(/^forget\s+(\S+)$/i)
  if (single) {
    const key = single[1].toUpperCase().startsWith(PREFIX) ? single[1].toUpperCase() : PREFIX + single[1].toUpperCase()
    if (!s.secrets.has(key)) return `redact: ${key} not stored`
    forget(s, key)
    return `redact: forgot ${key}`
  }
  const stored: string[] = []
  const rejected: string[] = []
  for (const line of args.split('\n')) {
    const m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*[=:]\s*(.+?)\s*$/)
    if (!m) { if (line.trim()) rejected.push(line.trim()); continue }
    const value = m[2].replace(/^(["'])(.*)\1$/, '$2')
    if (value.length < MIN_LENGTH) { rejected.push(`${m[1]} (value shorter than ${MIN_LENGTH})`); continue }
    if (value.includes(PREFIX)) { rejected.push(`${m[1]} (value contains ${PREFIX}, which marks placeholders)`); continue }
    stored.push(remember(s, m[1], value))
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

  // A hook that throws or times out is skipped by the engine, which would let raw
  // text through; the registration's catch withholds the prompt instead.
  on('prompt.submit', async ($, e, next) => {
    const s = await current($, autoDetect)
    if (COMMAND.test(e.text)) {
      let reply = command(s, e.text)
      await persist($, s)
      if (s.isDirty) reply += ' (in memory only, not saved yet: the session has no transcript until its first regular message)'
      $.ui.toast(reply, { timeoutMs: 8000 })
      return { drop: reply }
    }
    let context = e.context && concealAll(s, e.context, autoDetect)
    const known = s.secrets.size
    const text = conceal(s, e.text, autoDetect) // after context: a value learned there is replaced here too
    if (context && s.secrets.size !== known) context = mapStrings(context, x => replaceKnown(s, x))
    if (text === e.text && context === e.context && s.secrets.size === 0) {
      const r = await next(e)
      await persist($, s) // the history warning flag, when it was just shown
      return r
    }
    if (text !== e.text) $.ui.toast('redact: placeholders substituted in prompt')
    const r = await next({ ...e, text, context: [...(context ?? []), MODEL_NOTE] })
    await persist($, s) // after next(): a new session's transcript exists only now
    return r
  }).catch((_$, _e, next) => (next.called ? undefined : { drop: withheld('prompt', next.error) }))

  // On failure or timeout the tool does not run, or its result is withheld.
  on('tool.call', async ($, e, next) => {
    const s = await current($, autoDetect)
    const revealed = s.secrets.size && !MODEL_FACING.test(e.tool) ? mapStrings(e, x => reveal(s, x)) : e
    const r = await next(revealed)
    // Only `r` itself carries core's messages for the call (`ref`: a Skill's SKILL.md,
    // PostToolUse records). A rebuilt answer drops them, which is wanted once something
    // was masked: no hook can read or mask those messages.
    let answer: typeof r = r
    if (r.deny !== undefined) answer = { ...r, deny: conceal(s, r.deny, autoDetect) }
    else if (r.isError) {
      const text = r.text === undefined ? r.text : conceal(s, r.text, autoDetect)
      if (text !== r.text) answer = { deny: text! }
    } else {
      const result = concealAll(s, r.result, autoDetect)
      const text = r.text === undefined ? r.text : conceal(s, r.text, autoDetect)
      if (result !== r.result || text !== r.text) answer = { result, context: r.context } // the engine keeps context from next() whole
    }
    await persist($, s)
    return answer
  }).catch((_$, _e, next) => ({ deny: withheld(next.called ? 'tool result' : 'tool call', next.error) }))
}

function withheld(what: string, failure: { kind: string; message?: string }): string {
  return `redact: ${what} withheld, masking ${failure.kind === 'timeout' ? 'timed out' : `failed (${failure.message ?? 'unknown error'})`}`
}
