# redact

Backstory: [Redacted](https://scriptease.dev/posts/2026-09-05-redacted/).

Session-scoped redaction middleware, built as a Claude Code
[mod](https://code.claude.com/docs/en/plugins/mods/overview) (`hooks/redact.ts`).
Needs Claude Code v2.1.287 or later; mods are on by default. The model sees `REDACTED_<NAME>` placeholders; tools get
the real values.

## Install

```
claude plugin install redact --marketplace scriptease/claude-code-redact-plugin            # everywhere
claude plugin install redact --marketplace scriptease/claude-code-redact-plugin --scope local  # this project only
```

## Flow

| Event           | What happens                                                                                  |
| --------------- | --------------------------------------------------------------------------------------------- |
| `prompt.submit` | `redact NAME=value` prompts are dropped and stored. Other prompts: known values and auto-detected PII become placeholders; a note tells the model how to use them. |
| `tool.call`     | Placeholders in tool arguments (Bash command, file content, MCP args, ...) are replaced with the real values before the tool runs. Real values in the tool result are replaced with placeholders before the model reads it. |

## Storage

Secrets are bound to the session and survive a restart of the Claude process,
a `/reload-plugins` and a `--resume` days later. That is what headless hosts
(Agent SDK, T3 Code, `claude -p`) need: the process may be gone between turns.

- File: `~/.claude/projects/<project>/<session id>/redact.enc`, next to the
  transcript, written after every hook call that added a value (temp file,
  then `mv`, so a killed process leaves the previous file intact).
- Encryption: `/usr/bin/openssl` AES-256-CBC with PBKDF2. The mod runtime's
  `crypto.subtle` only offers `digest`. The session id is stored inside and
  checked on load.
- Key: one 256-bit key for all sessions in the login Keychain
  (`claude-code-redact` / `aes-key`), created on first use. It reaches
  `security` over stdin and `openssl` through its environment, never argv.
- A fork, `/branch` or `/clear` starts a new session id and starts empty.
- An unreadable file is moved to `redact.enc.corrupt-<ms>`; the session starts
  empty and old placeholders stay unresolved (fail-closed).

## Usage

```
redact DB_PASS=hunter2                  # store one (value: 4+ chars, quotes stripped)
redact API_TOKEN: "abc..."              # `=` or `:`; several NAME=value lines per prompt
redact list                             # placeholders currently stored
redact forget API_TOKEN                 # drop one
redact clear                            # drop all
```

Then talk in placeholders: `curl -H "Authorization: Bearer REDACTED_API_TOKEN" ...`.
Pasting the real value again is fine; it is rewritten before the model sees it.

Auto-detection (`autoDetect` option, default on) covers, in prompts and tool
results:

- by shape: e-mail addresses, IBANs, Luhn-valid card numbers, JWTs, common API
  key prefixes (`sk-`, `ghp_`, `github_pat_`, `AKIA`, `xox*-`, `glpat-`,
  `AIza`, Atlassian `ATATT3`), `Bearer` tokens, PEM private keys;
- by name, whatever the value looks like: credential headers (`Authorization`,
  `Proxy-Authorization`, `X-Api-Key`, `Api-Key`, `X-Auth-Token`,
  `X-Access-Token`, `Cookie`, `Set-Cookie`) in curl commands, HTTP dumps, trace
  entries and JSON header maps, and `key=value` / `key: value` pairs whose key
  contains `password`, `passwd`, `secret`, `token`, `api_key`,
  `access_key`, `private_key` or `credential` (env files, YAML, properties, URL
  query strings). References such as `$VAR`, `${...}` and `process.env.X` are
  left alone.

A value caught once is masked everywhere after that, in whatever form it shows
up again. Names, phone numbers and addresses are not detected; store those
explicitly.

## Limits

- The permission dialog shows the command as it will run, i.e. with real values (your terminal only).
- The engine's prompt queue record in the session `.jsonl` keeps the prompt as typed; the user/assistant messages hold placeholders. Prefer `redact NAME=value` over pasting secrets into a working prompt when the local transcript matters.
- A secret shorter than 4 characters is refused; substring collisions would rewrite too much.
- A secret containing `REDACTED_` is refused: that prefix marks placeholders, and a value shaped like one would make placeholders ambiguous.
- Every tool result is scanned once per stored value: cost grows with stored values × output size.
- `redact.enc` is capped at 4 MiB (roughly 30-40k stored values).
- macOS only (Keychain, `/usr/bin/openssl`).
- Tools whose input becomes another model's prompt (`Agent`, `SubagentHandback`, `SendMessage`, T3 Code's `delegate_task`, `t3_thread_send`, `t3_thread_launch`, `create_threads`, `schedule_task`) get placeholders, not values. A subagent runs in the same process and its own tool calls resolve them; another session or another provider cannot, so handing a secret to one does not work, by design.
- Everything else gets the real value, including what goes to people: a Slack, Jira or Gerrit CLI, a commit message, a rendered page. That is intended (post a customer's e-mail from an order lookup); keeping secrets out of those is up to the person driving the session. The model's own chat reply shows placeholders; have it copy, write or post the value to see it.
- Context another hook beneath this mod attaches to a tool result (a PostToolUse reminder, another plugin) reaches the model unmasked: the engine keeps a tool result's context from `next()` whole.
- If masking fails (the session id or the key cannot be read), the prompt is withheld or the tool call denied rather than passed through; Claude Code skips a hook that throws, which would let raw text through.
- Values that entered the session before redact was active stay readable to the model. The first hook of a session scans the history and warns once per detector version.

## Develop

```
claude --plugin-dir . --debug      # live reload on save
claude plugin validate .
/plugin-types .                    # writes .claude/types (gitignored), then: npx tsc -p tsconfig.json
```

Detection tests run the real module in the mod runtime:

```
claude plugin test .
```

`tests/detect.test.ts` holds two tables: `MASKED` (the secret must be gone and a
placeholder present) and `KEPT` (the text must pass unchanged). A new format is
one row, red first, then the pattern change.
