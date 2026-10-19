# secret-redact

A Claude Code plugin that redacts secrets **before the model reads them and before the transcript file stores them**. Each secret it finds is replaced with `[redacted:<kind>]`.

A `cat .env`, a `printenv`, a config file the agent opens, a key you paste into a prompt: without this, the value goes into the model's context and into `~/.claude/projects/**/*.jsonl` (and, for a prompt, `history.jsonl`) on disk. With it, they see only the marker.

## What it catches

- Supabase JWTs whose payload `role` is `service_role` (the public anon key passes), and `sb_secret_…` keys. A JWT-shaped token whose payload does not decode is redacted too, as `jwt-undecodable`.
- Anthropic `sk-ant-…` (OAuth `sk-ant-oat…` included), OpenAI `sk-…` / `sk-proj-…` (with at least one digit, so names like `sk-learn` pass)
- GitHub `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_`, Vercel `vcp_` / `vck_`, Linear `lin_api_` / `lin_oauth_`, AWS `AKIA…` / `ASIA…`
- `-----BEGIN … PRIVATE KEY-----` blocks
- the value in `NAME=value` (or `NAME = value`) when the UPPER_CASE name has a word ending in `KEY`, `SECRET`, `TOKEN`, `PASSWORD` or `PASSWD`: `PASSWORD`, `DB_PASSWORD`, `TOKEN_GITHUB`, `API_KEYS`, `KEY_2`, and glued forms like `APIKEY` or `ACCESSTOKEN`. The name may start anywhere a tool puts it: a `.env` line, `export` / `ENV` / `declare -x`, Grep's `3:` and `file:3:` prefixes, `cat -n`, a diff's `+` / `-`, a compose `- NAME=` item, docker inspect's `"NAME=value"`, a URL's `?NAME=`. The value is redacted to the end of its line, or to the closing quote of `"NAME=value"`.
- `"name": "<16+ chars, no spaces>"` in JSON when a word of the name ends in key, secret, token, password or passwd (`apiKey`, `client_secret`, `access-token`)

What passes on purpose:

- public names: `NEXT_PUBLIC_*`, names with an `ANON` word, `PUBLISHABLE` or `PUBLIC_KEY` (a secret value under one is still caught by its own pattern, such as a `service_role` JWT)
- names where the keyword is not a word ending: `MONKEY`, `TURKEY`, `HOTKEY` and the like, `KEYBOARD`, `TOKENIZER`, and `TOKENS` (`MAX_TOKENS` is a count)
- trivial values: empty, `true`, `false`, `null`, `none`, `yes`, `no`, `on`, `off`, `0`, `1`
- references: `$VAR`, `process.env…`, `os.environ…`, `os.getenv…`, `getenv(…)`, `env(…)`, `ENV[…]`, `<placeholder>`
- in `NAME = value` with spaces, which is more often code than `.env`: a plain number (`MAX_OUTPUT_TOKENS = 4096`) or a value that opens a list, dict or tuple; and comparisons (`==`, `=>`, `=~`)

Every rule runs in time linear in its input, and a test holds multi-megabyte inputs to a time bound, so a large tool output stays well inside a hook's time budget.

## How it works

It is a Claude Code mod: a TypeScript hooks module (`hooks/register.ts`) that Claude Code loads in-process, not a shell command hook. It hooks three places.

- **Every tool call**, subagents' included. For Bash, Read, Grep, Glob, Edit, Write, NotebookEdit, WebFetch, WebSearch and Agent it returns the same result with every string redacted. For any other tool (MCP tools included), for an errored result, and for a known tool whose text holds a secret its structured result does not, a hit withholds the result and the model gets only the redacted text.
- **Every prompt you submit**, before the prompt history (`history.jsonl`) records it. A slash command's line passes as typed, and so does a prompt you did not type (a delivery or notification), whose conversation row is still redacted.
- **Every conversation row** (pasted prompts, model text, deliveries, attachments) before it is written: text blocks and tool-result text are redacted.

It fails closed. If the redaction itself throws, the tool result is withheld and the prompt is not sent; for a conversation row, any block that even looks like it holds a secret is replaced by a notice.

A toast and the status line say how many values of which kinds were redacted. The values themselves are written nowhere.

## Install

From a running session:

```
/plugin marketplace add c10dev/secret-redact
/plugin install secret-redact@secret-redact
```

Or from a shell, for every session of this account:

```sh
claude plugin marketplace add c10dev/secret-redact
claude plugin install secret-redact@secret-redact --scope user
```

Each config folder keeps its own plugins, so with several accounts install it once per `CLAUDE_CONFIG_DIR`.

## Limits

- A secret outside these patterns passes: a bare `Bearer` token, a short or unlabelled password, a lowercase `name=value`, YAML `key: value`, keys inside escaped JSON.
- It does not change transcripts already written. Rotate any key that already reached one.
- What the model itself types into a tool call (a command, a Write's content) and thinking blocks are kept as written. An attachment's stored payload is kept as made; only what the model reads is redacted. A large Bash output persisted to a tool-results file is kept raw on disk; the model's read of it is redacted.
- When the agent edits or writes a file that holds secrets, Claude Code's checkpoint copy under `~/.claude/file-history/<session>/` keeps the original bytes raw.
- A prompt given on the command line to start a session (`claude '<prompt>'`) is recorded in `history.jsonl` before any hook runs, so it stays raw there, as it does in your shell history. The model and the transcript still get the marker. A slash command's arguments are kept as typed.
- A redacted line no longer matches the file on disk, so an Edit aimed at it fails. An env value is redacted to the end of its line, so the rest of a command line after it goes too. A `BEGIN … PRIVATE KEY` header with no `END` redacts the rest of the output.
- Plugins later in the hook order, and `PostToolUse` hooks in settings, may still see raw output.

This is a guard rail against accidental exposure, not a guarantee. Keep secrets out of places an agent reads where you can.

## Development

```sh
claude plugin validate --strict .   # manifest, marketplace file and hooks
claude plugin test .                # tests/*.test.ts, fake values only
tsc -p .                            # needs .claude-plugin/types/ (below); CI pins TypeScript 7.0.2
```

`claude --plugin-dir .` loads it for one session without installing. An interactive session also lays the type files `tsc` needs in `.claude-plugin/types/`; `claude -p` does not. CI's "Lay the mod type files" step is a scripted way. CI (`.github/workflows/ci.yml`) runs all three checks on a pinned Claude Code version.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
