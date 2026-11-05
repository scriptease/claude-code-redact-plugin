// Test plumbing: a fresh session per call, the engine answers the mod needs, and
// a bottom prompt.submit hook that records what the model would receive.
import type { TestBody } from 'claude-code/testing'

export type Engine = Parameters<TestBody>[0]
export type On = Parameters<TestBody>[1]
export type Delivered = { text: string; context: readonly string[] }

let sessions = 0

export function session(on: On, failing: { id?: boolean | 'hang'; messages?: boolean } = {}): Delivered[] {
  const id = `test-session-${++sessions}`
  const delivered: Delivered[] = []
  on('session.id', async () => {
    if (failing.id === 'hang') await new Promise(() => {})
    return failing.id ? { deny: 'session id unavailable' } : { value: id }
  })
  on('session.messages', async () => (failing.messages ? { deny: 'history read denied' } : { value: [] }))
  on('prompt.submit', async (_$, e) => {
    delivered.push({ text: e.text, context: e.context ?? [] })
    return { drop: 'captured' }
  })
  return delivered
}

export function submit($: Engine, text: string) {
  return $.prompt.submit({ text, wait: false, origin: { kind: 'sdk' } })
}
