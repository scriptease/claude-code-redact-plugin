# redact

Backstory: [Redacted](https://scriptease.dev/posts/2026-09-05-redacted/).

Session-scoped redaction middleware, built on Claude Code function hooks
(`hooks/redact.ts`). The model sees `REDACTED_<NAME>` placeholders; tools get
the real values.

## Flow

| Event           | What happens                                                                                  |
| --------------- | --------------------------------------------------------------------------------------------- |
| `prompt.submit` | `redact NAME=value` prompts are dropped and stored. Other prompts: known values and auto-detected PII become placeholders; a note tells the model how to use them. |
| `tool.call`     | Placeholders in tool arguments (Bash command, file content, MCP args, ...) are replaced with the real values before the tool runs. Real values in the tool result are replaced with placeholders before the model reads it. |

Storage is a `Map` inside the hooks module: it lives for the session only and
is gone on `/reload-plugins`, a module edit under `--plugin-dir`, or a new
session. Nothing is written to `$.store` or disk.

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

Auto-detection (`autoDetect` option, default on) covers e-mail addresses,
IBANs, Luhn-valid card numbers, JWTs, common API key prefixes (`sk-`, `ghp_`,
`github_pat_`, `AKIA`, `xox*-`, `glpat-`, `AIza`), `Bearer` tokens and PEM
private keys, in prompts and in tool results. Names, phone numbers and
addresses are not detected; store those explicitly.

## Limits

- The permission dialog shows the command as it will run, i.e. with real values (your terminal only).
- The engine's prompt queue record in the session `.jsonl` keeps the prompt as typed; the user/assistant messages hold placeholders. Prefer `redact NAME=value` over pasting secrets into a working prompt when the local transcript matters.
- A secret shorter than 4 characters is refused; substring collisions would rewrite too much.

## Develop

```
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir . --debug     # live reload on save
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude plugin validate .
/plugin-types .                    # writes .claude/types (gitignored), then: npx tsc -p tsconfig.json
```
