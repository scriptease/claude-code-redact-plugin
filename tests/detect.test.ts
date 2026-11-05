// What the redact mod masks in a prompt, run through the real module by `claude plugin test .`.
// Red/green: add a row to MASKED (must disappear) or KEPT (must pass unchanged).
// Fake tokens with real prefixes are assembled at runtime so secret scanners
// (GitHub push protection) do not flag this file.
import { describe, expect, test } from 'claude-code/testing'
import { session, submit } from './kit.ts'

const fake = (prefix: string, length: number) => prefix + 'Ab3dE5gH7jK9mN1pQ2rS4tU6vW8xY0z'.repeat(8).slice(0, length - prefix.length)

const GITHUB = fake('gh' + 'p_', 40)
const OPENAI = fake('s' + 'k-', 40)
const AWS = 'AK' + 'IA' + 'Q3EXAMPLE7KEY2ID'
const ATLASSIAN = fake('ATA' + 'TT3', 64)
const JWT = ['ey' + 'JhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'].join('.')
const PEM = ['-----BEGIN ' + 'PRIVATE KEY-----', 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', '-----END ' + 'PRIVATE KEY-----'].join('\n')

type Masked = { name: string; text: string; secret: string; placeholder?: RegExp }
type Kept = { name: string; text: string }

const MASKED: Masked[] = [
  // by header name
  { name: 'curl Authorization Bearer', text: 'curl -H "Authorization: Bearer abc123customtoken" https://x', secret: 'abc123customtoken', placeholder: /REDACTED_AUTHORIZATION_\d+/ },
  { name: 'lowercase authorization header', text: 'authorization: Bearer lowercasedtoken42', secret: 'lowercasedtoken42' },
  { name: 'X-Api-Key header', text: "curl -H 'X-Api-Key: k9-not-a-known-prefix' https://x", secret: 'k9-not-a-known-prefix', placeholder: /REDACTED_X_API_KEY_\d+/ },
  { name: 'JSON header map, Basic', text: '{"Authorization":"Basic dXNlcjpwYXNzd29yZA==","Accept":"json"}', secret: 'dXNlcjpwYXNzd29yZA==' },
  { name: 'Java trace header map', text: 'TRACE headers={Authorization=Bearer t0k3nvalue99, Accept=*/*}', secret: 't0k3nvalue99' },
  { name: 'Cookie header', text: 'Cookie: JSESSIONID=ABCDEF123456; theme=dark', secret: 'JSESSIONID=ABCDEF123456' },
  // by key name
  { name: 'env DB_PASSWORD', text: 'DB_PASSWORD=hunter2isfine', secret: 'hunter2isfine', placeholder: /REDACTED_DB_PASSWORD_\d+/ },
  { name: 'export JIRA_API_TOKEN', text: 'export JIRA_API_TOKEN="short-jira-tok"', secret: 'short-jira-tok' },
  { name: 'API_KEY: value', text: 'API_KEY: plainvalue123', secret: 'plainvalue123' },
  { name: 'Spring properties password', text: 'spring.datasource.password: s3cr3tpw', secret: 's3cr3tpw' },
  { name: 'YAML client_secret', text: '  client_secret: "c1i3nt-s3cr3t-v4lue"', secret: 'c1i3nt-s3cr3t-v4lue' },
  { name: 'api_key in URL query', text: 'https://api.x/v1?api_key=qwertyuiop&page=2', secret: 'qwertyuiop' },
  // by shape, no name around
  { name: 'GitHub ghp_ token', text: `token is ${GITHUB}`, secret: GITHUB },
  { name: 'OpenAI sk- key', text: OPENAI, secret: OPENAI },
  { name: 'AWS access key id', text: `aws ${AWS}`, secret: AWS },
  { name: 'Atlassian ATATT3 token', text: `jira ${ATLASSIAN}`, secret: ATLASSIAN },
  { name: 'JWT', text: `got ${JWT} back`, secret: JWT },
  { name: 'PEM private key', text: `key:\n${PEM}\n`, secret: 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' },
  { name: 'Bearer without header name', text: 'use Bearer Zx9Yw8Vu7Ts6Rq5Po4Nm', secret: 'Zx9Yw8Vu7Ts6Rq5Po4Nm' },
  { name: 'e-mail address', text: 'customer: jane.doe+orders@example.org', secret: 'jane.doe+orders@example.org' },
  { name: 'IBAN', text: 'pay to DE89370400440532013000', secret: 'DE89370400440532013000' },
  { name: 'Luhn-valid card number', text: 'card 4111 1111 1111 1111', secret: '4111 1111 1111 1111' },
  // review round 1
  { name: 'numeric password, not a count', text: '{"password":"842196"}', secret: '842196' },
  { name: 'literal password starting with $', text: '{"password":"$tR0ng!42"}', secret: '$tR0ng!42' },
  { name: 'quoted password with semicolon', text: 'DB_PASSWORD="ab;tailSecret42"', secret: 'ab;tailSecret42' },
  { name: 'quoted passphrase, whole value', text: 'DB_PASSWORD="correct horse battery staple"', secret: 'horse battery staple' },
  { name: 'bare repeat after a labelled password', text: 'DB_PASSWORD=opaque-secret-42\nAgain opaque-secret-42', secret: 'opaque-secret-42' },
  // review round 2
  { name: 'JSON password with escaped quote', text: String.raw`{"password":"abc\"tailSecret42"}`, secret: 'tailSecret42' },
]

const KEPT: Kept[] = [
  { name: 'process.env reference', text: 'const token: string = process.env.TOKEN' },
  { name: 'shell variable reference', text: 'DB_PASSWORD=$DB_PASS' },
  { name: 'empty password', text: '"password": ""' },
  { name: 'numeric token count', text: 'tokenCount: 1234' },
  { name: 'PWD path', text: 'PWD=/Users/florian/github/x OLDPWD=/Users/florian' },
  { name: 'ATATT3 shorter than 31 characters', text: 'ATA' + 'TT3xFfGF0shortvalue' },
  { name: 'git SHA', text: 'commit 0524443a9c1f3e2d7b6a5c4d3e2f1a0b9c8d7e6f' },
  { name: 'UUID', text: 'session 669fb315-79dd-4131-96c6-6b4b891c82ce' },
  { name: 'card number failing Luhn', text: 'order 4111 1111 1111 1112' },
  { name: 'plain URL', text: 'see https://example.org/docs/page?lang=en' },
  { name: 'max_tokens count', text: 'max_tokens: 4096' },
  { name: 'braced shell variable reference', text: 'DB_PASSWORD=${DB_PASS}' },
]

describe('masked', () => {
  for (const c of MASKED) {
    test(c.name, async ($, on) => {
      const delivered = session(on)
      await submit($, c.text)
      const seen = delivered[0]?.text ?? ''
      expect(seen.includes(c.secret)).toBe(false)
      expect(seen).toMatch(c.placeholder ?? /REDACTED_[A-Z0-9_]+/)
    })
  }
})

describe('kept', () => {
  for (const c of KEPT) {
    test(c.name, async ($, on) => {
      const delivered = session(on)
      await submit($, c.text)
      expect(delivered[0]?.text).toBe(c.text)
    })
  }
})
