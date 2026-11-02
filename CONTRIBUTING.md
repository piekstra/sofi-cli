# Contributing to sofi-cli

Thanks for your interest! Contributions — bug reports, fixes, new commands,
docs — are welcome under the project's dual [MIT](LICENSE-MIT) /
[Apache-2.0](LICENSE-APACHE) license: by opening a pull request you agree your
contribution is licensed under those same terms.

## Ground rules (this reads a real household's bank accounts)

- **Never commit secrets or personal data.** Passwords, session cookies,
  device ids, account numbers, balances, and transactions live only in the OS
  keychain or in memory. Nothing credential-like or identifying belongs in
  the repo, tests, fixtures, or commit messages.
- **Fixtures are synthetic, not captures.** See
  [`tests/fixtures/README.md`](tests/fixtures/README.md) — they model public
  community documentation, with citations, and a test enforces that every
  identity-bearing field holds an obvious dummy. If you ever capture a real
  response to check a shape, scrub it before it touches the working tree, and
  never commit the raw file.
- **Read-only, and that is load-bearing.** This tool must never move money,
  pay a bill, or change account settings. `sfi api` allows `GET` only. If a
  write is ever added, the README's read-only claim has to change *in the
  same commit*.
- **Secrets never on argv or in logs.** Read them from the keychain or stdin.

## Dev loop

```console
$ make verify     # fmt-check + clippy -D warnings + tests + smoke — the CI gate
$ make test       # unit + integration (fully offline; no network, no creds)
$ make dev        # debug build, re-signed so keychain grants survive rebuilds
$ cargo run -- <command>
```

`make verify` is exactly what CI runs; a green local run predicts a green CI
run.

## Pull requests

1. Branch from `main`; keep the change focused.
2. Add or update tests. Contract tests load fixtures from disk — extend
   `tests/fixtures/` (synthetic!) rather than inlining JSON blobs in test code.
3. Keep the human table and the `--json` DTO in sync. A breaking DTO change
   bumps its `schema` version suffix.
4. Update [`docs/api.md`](docs/api.md) when you learn something new about the
   API, and the README when you change the command surface. If you *verify*
   something currently marked UNVERIFIED-LIVE, move it and say how you
   confirmed it.
5. Run `make verify` and include what you tested.

## A note on the provider

SoFi publishes **no public API for member accounts**. Everything here is
built against thin community reverse-engineering, so it can break without
notice, and the login flow in particular is MFA-gated and bot-protected. If a
command starts failing, check `docs/api.md` against current community sources
before assuming the bug is local.

**Do not test by hammering the login endpoint.** Every live login costs the
account owner an SMS/email code, and repeated attempts risk rate limiting or
an account lock. The whole test suite is offline for exactly that reason;
please keep it that way, and ask before spending a live login.
