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
closes as soon as the session is read; then Chrome quits. Ctrl-C cancels and
stops Chrome. Nothing drives the page: you log in by hand, which is what keeps
the anti-bot checks happy. The window and the capture come from cli-common's
`pk-cli-browser`, shared across the CLI family. It needs Google Chrome (or set
`SFI_CHROME` to a Chrome/Chromium/Edge binary).

**The profile is kept.** Chrome runs in a profile `sfi` keeps on disk, owner-only
(`0700`), at `~/Library/Application Support/piekstra.sfi/browser-profile` on
macOS and `$XDG_DATA_HOME/piekstra.sfi/browser-profile` (or under
`~/.local/share`) on Linux. SoFi's own cookies stay there between sign-ins, so
a later `--browser` asks for less, often nothing: the window opens, the app
loads signed in, the session is read and the window closes. On Windows every
sign-in uses a scratch profile.

That is a trade: far fewer sign-ins, for a full Chrome profile on disk. Besides
SoFi's cookies, it holds browsing history with full URLs including query
strings, the HTTP cache and site storage. Chrome's cookie encryption does not
cover those, so `0700` is their only protection, and the directory is one
ordinary backups usually include. On Linux with no desktop keyring, Chrome
encrypts cookies with a fixed, publicly known key, so `0700` is all that protects
the session cookie too: use `--fresh-profile` there. See
[SECURITY.md](SECURITY.md).

- `sfi auth login --browser --fresh-profile` signs in through a scratch profile
  deleted afterwards, and leaves the kept one alone. SoFi sees a new device, so
  expect its full sign-in.
- `sfi auth logout` removes the kept profile too, so the next sign-in starts
  signed out. It refuses while a sign-in or a Chrome is using the profile (exit
  1): the keychain session is already cleared and only the profile remains, so
  close that window and log out again.
- A sign-in that fails for any reason, Ctrl-C included, leaves the kept profile
  in place, possibly signed in, and its error says so. `sfi auth logout` removes
  it, and clears the stored session too. `sfi auth status` does not report the
  profile.

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
sfi mcp [--list-tools]                    # read-only tools for Claude
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

## Use with Claude

`sfi mcp` serves four read-only tools over MCP, so Claude can answer
questions about your own SoFi Checking & Savings. There is no hosted
service: the tools run on your computer, in your copy of `sfi`, and call
SoFi's web API directly with the session `sfi auth login --browser` stored in
your OS keychain.

| Tool | Answers |
| --- | --- |
| `sofi_balances` | How much cash is at SoFi? Each open account's available balance and APY, with the total, narrowed by `account` (its name) |
| `sofi_transactions` | What did I spend and receive over a period? Settled transactions by `since`/`until` dates (year to date by default), `account` and `type` |
| `sofi_interest` | How much interest did a year pay (the 1099-INT figure)? This year is SoFi's own running figure; a past year sums its interest payments |
| `sofi_documents` | Which monthly statements exist? Listed by `since`/`until`, never downloaded (`sfi documents download` does that). Tax forms are not in this list |

Results are concise by default (`response_format: "detailed"` adds the
posted balance, the masked number and ids), 25 records a page with a cursor
for more, and never larger than about 32,000 characters. Accounts are named,
not numbered. Descriptions come from SoFi; the server tells Claude to treat
them as data, not instructions. A past year's interest rests on recognising
interest payments among the transactions, which is unverified against a
live account (docs/api.md §3.4).

**Sign in first.** SoFi sign-in is through a browser, so no settings form can
hold it. Install `sfi` and run `sfi auth login --browser` in a terminal (see
[Login (browser)](#login-browser)). Both ways of connecting Claude below
then use that session from the OS keychain (service `piekstra.sfi`). If the
session is missing or has expired, the tools say so and ask you to run
`sfi auth login --browser` in a terminal; they never sign in by themselves.

**Claude Code.** Add the `sofi-cli` plugin from the
[piekstra plugin marketplace](https://github.com/piekstra/claude-plugins):

```console
$ claude plugin marketplace add piekstra/claude-plugins
$ claude plugin install sofi-cli@piekstra-plugins
```

or register the server yourself:

```console
$ claude mcp add sofi -- sfi mcp
```

**Claude Desktop.** Download `sfi-<version>.mcpb` from the
[latest release](https://github.com/piekstra/sofi-cli/releases/latest) and
open it. It asks for nothing: the bundled `sfi` reads the session your
installed `sfi` stored. On macOS the bundled binary is a different program
to the keychain, so its first call raises a keychain prompt for the
`piekstra.sfi` item; choose **Always Allow**, or every call will ask again.

Any other MCP client that launches a local server can run `sfi mcp`.

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
