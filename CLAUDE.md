# CLAUDE.md

The canonical agent guide for this repo is **[AGENTS.md](AGENTS.md)** — read it
first. It covers build/test/lint, layout, conventions, and the safety rules.

Claude Code specifics:

- **Gate on `make verify`.** Don't report a change as done until it's green
  (fmt + clippy `-D warnings` + tests + smoke). Tests are fully offline.
- **This CLI is read-only, and that is a safety property.** It reads a real
  household's bank accounts. Never add transfers, payments, or settings
  changes; `sfi api` is GET-only by design.
- **Secrets:** password, session cookies, device id, and any parked mid-MFA
  login live in the OS keychain (`piekstra.sfi`). Never print one, put it on
  argv, or write it to a file — including while debugging.
- **A live login costs the owner an SMS/email code** and risks rate limiting
  or lockout. There is no retry loop anywhere in the auth path, on purpose.
  Prefer the offline fixtures; **ask before spending a live login.**
- **Unofficial API.** SoFi publishes no public member API, so treat
  `docs/api.md` as a best-effort model, not a contract. Anything marked
  **UNVERIFIED-LIVE** has never been confirmed against the real service — do
  not describe it as working.
- **Never claim success without positive confirmation.** 200-with-HTML is an
  auth failure; a "downloaded" file that doesn't start with `%PDF` is not a
  statement.
- **Written as if public.** No real account numbers, balances, transactions,
  names, or emails in any diff — including test fixtures (dummies only).
