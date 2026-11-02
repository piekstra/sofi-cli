# sofi-cli (`sfi`)

Read-only command-line access to **SoFi Checking & Savings** — the
household's primary cash accounts — for the money map: cash balances for the
emergency-fund analysis, YTD interest for 1099-INT reconciliation,
transactions for spending ingestion, and statements/tax forms at season.

Conforms to `piekstra-cli` spec v1 (see
[cli-common](https://github.com/piekstra/cli-common)), so `--json`, exit
codes, `auth`, `config`, `self-update`, `completions`, and `info` all behave
the way the rest of the family does.

Unofficial; not affiliated with or endorsed by SoFi Technologies, Inc.

> [!IMPORTANT]
> **SoFi publishes no public API for member accounts.** Everything here is
> built on thin community reverse-engineering, so it can break without
> notice, and using it carries provider-side risk (rate limiting, MFA
> challenges, account restrictions). Read [`docs/api.md`](docs/api.md) before
> first use — it records the auth flow, the endpoints, the honest failure
> modes, and which commands are still **UNVERIFIED-LIVE** (currently:
> `documents download`, and the transactions date fix awaiting one live read).

> [!NOTE]
> **Read-only, enforced in code.** `sfi` never moves money, pays a bill, or
> changes account settings; `sfi api` accepts `GET` only.

## Install

```console
$ make install          # builds, installs to ~/.cargo/bin, re-signs for keychain
$ sfi --help
```

## Getting started

```console
# 1. Log in through a browser (the supported path — see below).
$ sfi auth login --browser

# 2. Confirm, and see what the login contains.
$ sfi auth status --verify
$ sfi accounts list
```

## Login (browser)

SoFi's login sits behind **Auth0 + Cloudflare + ThreatMetrix** with SMS MFA —
there is no scriptable login endpoint (the plausible one returns 404 live), so
`sfi` logs in the way every SoFi tool does: it borrows a real browser sign-in.

```console
$ sfi auth login --browser
```

A Chrome window opens at the SoFi login. **You** sign in there (password and
the texted code). `sfi` waits up to 10 minutes for the app at `www.sofi.com`,
reads the `sofi.com` session cookies over the Chrome DevTools Protocol,
confirms them with one read, and stores them in the OS keychain. The tab
closes as soon as the session is read; then Chrome quits and its throwaway
profile is deleted. Ctrl-C cancels and cleans up. Nothing drives the page:
you log in by hand, which is what keeps the anti-bot checks happy. The window
and the capture come from cli-common's `pk-cli-browser`, shared across the CLI
family. It needs Google Chrome (or set `SFI_CHROME` to a Chrome/Chromium/Edge
binary).

Login and the balance / interest / statement-list reads are **verified live**
(2026-08-24). While you are signed in, `sfi` also watches the app's pages for
a real `/bff/graphql` request and records its header recipe, so
`transactions` sends the exact headers SoFi's BFF requires. If the app has not
made one by the time the session is in place, the tab stays open up to 25
seconds for it. That read answers live (2026-08-31). Each row carries an ISO
`date`, a signed `amount`, the provider's `kind`, and the `merchant` when the
app shows one (see [`docs/api.md`](docs/api.md) §3.4).

> [!NOTE]
> `sfi auth login` without `--browser` runs a modeled password/`--code` flow
> whose endpoint is **dead** (confirmed 404 live). It is retained only for the
> day SoFi might expose a scriptable login; use `--browser`.

## Commands

```
sfi auth login|status|logout|set-credential
sfi config path|show|set|unset
sfi accounts list|get [ID]
sfi net-worth                             # cash balances, rolled up (net-worth/v1)
sfi interest list [--since D] [--until D]      # 1099-INT raw material
sfi interest ytd [--year YYYY]                 # the year's total so far
sfi transactions list [--since D] [--until D] [--limit N]
sfi documents list|download               # statements & tax forms
sfi api GET <PATH>                        # raw read-only passthrough
sfi self-update | completions <shell> | info
```

Every command takes `--json`, `-v/--verbose`, `-q/--quiet`, and `--no-color`.
`-a/--account <ID>` (env `SFI_ACCOUNT`) selects one account — checking or
savings — where that makes sense.

### Money-map use

```console
# Cash position for the emergency-fund analysis: every account's
# provider-reported balance, rolled up (same DTO as rhd/m1f net-worth).
$ sfi net-worth --json

# Interest for the 1099-INT workup.
$ sfi interest ytd --json
$ sfi interest list --since 2026-01-01 --json

# Spending raw material.
$ sfi transactions list --since 2026-07-01 --until 2026-07-31 --json

# Statements at season.
$ sfi documents list --json
$ sfi documents download <ID> -o ~/tax/2026/sofi-statement.pdf
```

Downloads are verified by magic bytes: if the payload does not begin with
`%PDF`, `sfi` fails rather than writing a file and claiming success.

## Security

The password, session, and device id live only in the OS keychain
(`piekstra.sfi`). Nothing sensitive is ever accepted on argv or written to
disk. See [`SECURITY.md`](SECURITY.md).

```console
$ op read 'op://Private/sofi/password' \
    | sfi auth set-credential --stdin --overwrite
```

## Development

```console
$ make verify     # fmt-check + clippy -D warnings + test + smoke — the CI gate
```

The test suite is **fully offline** — no network, no keychain, no credentials
— because testing against the live service costs the account owner an
SMS/email code. Fixtures are synthetic, built from public community
documentation with citations in
[`tests/fixtures/README.md`](tests/fixtures/README.md).

See [`AGENTS.md`](AGENTS.md) for the full working agreement and
[`CONTRIBUTING.md`](CONTRIBUTING.md) to contribute.

## License

MIT or Apache-2.0, at your option.
