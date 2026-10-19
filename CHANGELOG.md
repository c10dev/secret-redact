# Changelog

## 0.1.1

Fixes leaks of `.env`-style secrets found by an independent check of 0.1.0.

- The env rule now catches names that start with the keyword (`PASSWORD=`, `TOKEN=`, `SECRET=`, `KEY=`, `PASSWD=`, `TOKEN_GITHUB=`, `export PASSWORD=`). 0.1.0 passed their values raw.
- The env rule now finds a name anywhere on a line, not only at its start, so Grep's `3:` and `file:3:` prefixes, `cat -n`, diff `+` / `-` lines, `ENV`, compose `- NAME=` items, docker inspect's `"NAME=value"`, URL queries and `NAME = value` no longer hide a value. A name it lets pass no longer hides a secret later on the same line.
- A typed prompt is redacted before the prompt history (`history.jsonl`) records it (new `prompt.submit` hook; slash commands pass as typed). If redaction fails, the prompt is not sent.
- The keyword must end a word of the name, so `MONKEY_NAME`, `TURKEY_COUNT`, `KEYBOARD_*`, `"tokenizer"`, `MAX_TOKENS` and `"max_tokens_limit"` pass. With spaces around `=`, a plain number or an opening `[`, `{` or `(` passes (`MAX_OUTPUT_TOKENS = 4096`).
- The JSON and env rules are linear in their input. 0.1.0 took seconds on 120 KB of `"keykey…` or `AKEYKEY…`, enough to run out a hook's budget (the result was withheld, not leaked). A test now holds 3 MB inputs to a time bound.
- Toasts and the status line no longer repeat the plugin name the engine already shows.
- README: documents everything caught and passed (`ghu_` / `ghr_`, `PASSWD`, `jwt-undecodable`, public names, trivial values, references), raw copies in `~/.claude/file-history`, command-line prompts in `history.jsonl`, and that only an interactive session lays the type files.

## 0.1.0

First standalone release, moved out of compute-pool.

- Redacts Supabase `service_role` JWTs and `sb_secret_` keys, Anthropic, OpenAI, GitHub, Vercel, Linear and AWS access keys, PEM private key blocks, and secret values in `.env` lines and JSON config files.
- Hooks every tool call (subagents included) and every conversation row before it is stored.
- Fails closed: if redaction itself fails, the tool result is withheld.
- Toasts and the status line report how many values of which kinds were redacted, never the values.
