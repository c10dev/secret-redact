# Changelog

## 0.1.0

First standalone release, moved out of compute-pool.

- Redacts Supabase `service_role` JWTs and `sb_secret_` keys, Anthropic, OpenAI, GitHub, Vercel, Linear and AWS access keys, PEM private key blocks, and secret values in `.env` lines and JSON config files.
- Hooks every tool call (subagents included) and every conversation row before it is stored.
- Fails closed: if redaction itself fails, the tool result is withheld.
- Toasts and the status line report how many values of which kinds were redacted, never the values.
