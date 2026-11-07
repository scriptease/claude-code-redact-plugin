// Hook behavior beyond single-prompt detection: failure handling, tool results,
// stateful sequences and timing. Run by `claude plugin test .`.
import { describe, expect, test } from 'claude-code/testing'
import { session, submit } from './kit.ts'

const leaks = (value: unknown, secret: string) => JSON.stringify(value ?? null).includes(secret)

describe('fails closed', () => {
  test('history read fails: the prompt is still masked', async ($, on) => {
    const delivered = session(on, { messages: true })
    await submit($, 'DB_PASSWORD=opaque-secret-42')
    expect(leaks(delivered, 'opaque-secret-42')).toBe(false)
  })

  test('session id fails: the prompt is dropped, not passed raw', async ($, on) => {
    const delivered = session(on, { id: true })
    const r = await submit($, 'DB_PASSWORD=opaque-secret-42')
    expect(leaks(delivered, 'opaque-secret-42')).toBe(false)
    expect(r).toHaveProperty('drop')
  })

  test('session id never answers: the prompt is withheld', { timeoutMs: 30000 }, async ($, on) => {
    const delivered = session(on, { id: 'hang' })
    const r = await submit($, 'DB_PASSWORD=opaque-secret-50')
    expect(leaks(delivered, 'opaque-secret-50')).toBe(false)
    expect(JSON.stringify(r)).toContain('redact: prompt withheld')
  })

  test('session id fails: a tool result is withheld, not passed raw', async ($, on) => {
    session(on, { id: true })
    on('tool.call', async () => ({ result: 'DB_PASSWORD=opaque-secret-42' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(leaks(r, 'opaque-secret-42')).toBe(false)
  })
})

describe('tool results', () => {
  test('bare value before its labelled occurrence', async ($, on) => {
    session(on)
    on('tool.call', async () => ({ result: { echo: 'opaque-secret-43', credentials: 'DB_PASSWORD=opaque-secret-43' } }))
    const r = await $.tool.call({ tool: 'Bash', command: 'x' })
    expect(leaks(r, 'opaque-secret-43')).toBe(false)
  })

  test('deny text is masked', async ($, on) => {
    session(on)
    on('tool.call', async () => ({ deny: 'Denied command opaque-secret-44' }))
    await submit($, 'redact PASS=opaque-secret-44')
    expect(leaks(await $.tool.call({ tool: 'Bash', command: 'x' }), 'opaque-secret-44')).toBe(false)
  })

  // ref names core's messages for the call (a Skill's SKILL.md, PostToolUse records); a
  // rebuilt answer loses them, so a result with nothing to mask must pass as the same object.
  test('clean result keeps ref', async ($, on) => {
    session(on)
    on('tool.call', async () => ({ ref: 7, result: 'Launching skill: x', text: 'Launching skill: x' }))
    expect(await $.tool.call({ tool: 'Bash', command: 'x' })).toHaveProperty('ref', 7)
  })

  test('clean error keeps ref', async ($, on) => {
    session(on)
    on('tool.call', async () => ({ ref: 8, isError: true as const, result: 'exit 1', text: 'exit 1' }))
    expect(await $.tool.call({ tool: 'Bash', command: 'x' })).toHaveProperty('ref', 8)
  })

  test('masked result drops ref: core messages are not masked', async ($, on) => {
    session(on)
    on('tool.call', async () => ({ ref: 9, result: 'DB_PASSWORD=opaque-secret-51', text: 'DB_PASSWORD=opaque-secret-51' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'x' })
    expect(leaks(r, 'opaque-secret-51')).toBe(false)
    expect(r).not.toHaveProperty('ref')
  })

  // Skill args land in the skill's text, which core hands the model unmasked.
  test('Skill args keep placeholders', async ($, on) => {
    session(on)
    let input = ''
    on('tool.call', async (_$, e) => { input = JSON.stringify(e); return { result: 'Launching skill: x' } })
    await submit($, 'redact PASS=opaque-secret-52')
    await $.tool.call({ tool: 'Skill', skill: 'x', args: 'use REDACTED_PASS' })
    expect(input).toContain('REDACTED_PASS')
    expect(input).not.toContain('opaque-secret-52')
  })

  test('object keys are masked', async ($, on) => {
    session(on)
    on('tool.call', async () => ({ result: { 'opaque-secret-45': 'matched' } }))
    await submit($, 'redact CUSTOMER=opaque-secret-45')
    expect(leaks(await $.tool.call({ tool: 'Bash', command: 'x' }), 'opaque-secret-45')).toBe(false)
  })
})

describe('sessions', () => {
  test('auto-detection does not overwrite a manually named secret', async ($, on) => {
    const delivered = session(on)
    await submit($, 'redact EMAIL_1=opaque-secret-46')
    await submit($, 'mail jane@example.org')
    await submit($, 'again opaque-secret-46')
    expect(leaks(delivered, 'opaque-secret-46')).toBe(false)
  })

  test('a value learned from prompt context is masked in the prompt text', {
    plugins: [{
      name: 'adds-context',
      tier: 'prepend',
      register: on => { on('prompt.submit', async (_$, e, next) => next({ ...e, context: [...(e.context ?? []), 'DB_PASSWORD=opaque-secret-49'] })) },
    }],
  }, async ($, on) => {
    const delivered = session(on)
    await submit($, 'Use opaque-secret-49')
    expect(leaks(delivered, 'opaque-secret-49')).toBe(false)
  })

  test('a stored value never rewrites a placeholder name', async ($, on) => {
    const delivered = session(on)
    let command = ''
    on('tool.call', async (_$, e) => { command = 'command' in e ? String(e.command) : ''; return { result: 'ok' } })
    await submit($, 'redact PASS=EMAIL')
    await submit($, 'mail jane@example.org')
    await submit($, 'mail jane@example.org')
    expect(delivered.map(d => d.text)).toEqual(['mail REDACTED_EMAIL_1', 'mail REDACTED_EMAIL_1'])
    await $.tool.call({ tool: 'Bash', command: delivered[1]?.text ?? '' })
    expect(command).toBe('mail jane@example.org')
  })

  test('a value containing REDACTED_ is refused, not stored', async ($, on) => {
    const delivered = session(on)
    const r = await submit($, 'redact PASS=REDACTED_BACKUP_2026-secret')
    expect(JSON.stringify(r)).toContain('marks placeholders')
    await submit($, 'Use REDACTED_PASS')
    expect(delivered.at(-1)?.text).toBe('Use REDACTED_PASS')
  })

  test('the model note reaches the model with the prompt', async ($, on) => {
    const delivered = session(on)
    await submit($, 'DB_PASSWORD=opaque-secret-47')
    expect(delivered[0]?.context.some(c => c.startsWith('Tokens of the form REDACTED_'))).toBe(true)
  })

  test('a registration that cannot be saved yet says so', async ($, on) => {
    session(on)
    const r = await submit($, 'redact PASS=opaque-secret-48')
    expect(JSON.stringify(r)).toContain('not saved yet')
  })
})

describe('linear time', () => {
  const inputs: [string, string][] = [
    ['underscore-separated noise', 'abc_'.repeat(16000)],
    ['header followed by long whitespace', 'Authorization: a' + ' '.repeat(64000) + 'z'],
    ['dot-separated noise', 'a.'.repeat(32000)],
    ['dash-separated noise', 'ab-'.repeat(21000)],
  ]
  for (const [name, text] of inputs) {
    test(`${name} (64 KB) under 1 s`, async ($, on) => {
      session(on)
      const start = performance.now()
      await submit($, text)
      expect(performance.now() - start).toBeLessThan(1000)
    })
  }
})
