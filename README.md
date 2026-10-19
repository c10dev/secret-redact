# secret-redact

A Claude Code plugin that redacts secrets **before the model reads them and before the transcript file stores them**. Each secret it finds is replaced with `[redacted:<kind>]`.

A `cat .env`, a `printenv`, a config file the agent opens, a key you paste into a prompt: without this, the value goes into the model's context and into `~/.claude/projects/**/*.jsonl` on disk. With it, both see only the marker.

## What it catches

- Supabase JWTs whose payload `role` is `service_role` (the public anon key passes), and `sb_secret_…` keys
- Anthropic `sk-ant-…` (OAuth `sk-ant-oat…` included), OpenAI `sk-…` / `sk-proj-…`
- GitHub `ghp_` / `gho_` / `ghs_` / `github_pat_`, Vercel `vcp_` / `vck_`, Linear `lin_api_` / `lin_oauth_`, AWS `AKIA…` / `ASIA…`
- `-----BEGIN … PRIVATE KEY-----` blocks
- the value of a `.env` line whose UPPER_CASE name holds `KEY`, `SECRET`, `TOKEN` or `PASSWORD` (but not `NEXT_PUBLIC_*`, anon or publishable names, or `$VAR` references)
- `"…key|secret|token|password…": "<16+ chars>"` in JSON config files

Every pattern is linear (no nested quantifiers), so a multi-megabyte tool output stays well inside a hook's time budget.

## How it works

It is a Claude Code mod: a TypeScript hooks module (`hooks/register.ts`) that Claude Code loads in-process, not a shell command hook. It hooks two places.

- **Every tool call**, subagents' included. For Bash, Read, Grep, Glob, Edit, Write, NotebookEdit, WebFetch, WebSearch and Agent it returns the same result with every string redacted. For any other tool (MCP tools included), and for an errored result, a hit withholds the result and the model gets only the redacted text.
- **Every conversation row** (pasted prompts, model text, deliveries, attachments) before it is written: text blocks and tool-result text are redacted.

It fails closed. If the redaction itself throws, the tool result is withheld; for a conversation row, any block that even looks like it holds a secret is replaced by a notice.

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

- A secret outside these patterns passes: a bare `Bearer` token, a short or unlabelled password, YAML `key: value`, keys inside escaped JSON.
- It does not change transcripts already written. Rotate any key that already reached one.
- What the model itself types into a tool call (a command, a Write's content) and thinking blocks are kept as written. An attachment's stored payload is kept as made; only what the model reads is redacted. A large Bash output persisted to a tool-results file is kept raw on disk; the model's read of it is redacted.
- A redacted line no longer matches the file on disk, so an Edit aimed at it fails. A `BEGIN … PRIVATE KEY` header with no `END` redacts the rest of the output.
- Plugins later in the hook order, and `PostToolUse` hooks in settings, may still see raw output.

This is a guard rail against accidental exposure, not a guarantee. Keep secrets out of places an agent reads where you can.

## Development

```sh
claude plugin validate --strict .   # manifest, marketplace file and hooks
claude plugin test .                # tests/*.test.ts, fake values only
tsc -p .                            # needs .claude-plugin/types/, laid by Claude Code when it loads the mod
```

`claude --plugin-dir .` loads it for one session without installing. That session also lays the type files `tsc` needs. CI (`.github/workflows/ci.yml`) runs all three checks on a pinned Claude Code version.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
