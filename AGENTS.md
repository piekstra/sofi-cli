# AGENTS.md — working agreement for `sofi-cli`

Canonical agent guide for this repo. `CLAUDE.md` is a thin pointer here.

## What this is

`sfi` is a **read-only** CLI over SoFi's **unofficial, thinly
community-documented** private API — the one its own web app uses. SoFi holds
the household's primary cash accounts (checking + savings), and this CLI
exists to feed the tax/money-optimizer pipeline:

- **cash balances for the emergency-fund analysis** — `net-worth` emits the
  family's `net-worth/v1` DTO (same shape as `rhd net-worth` and
  `m1f net-worth`), one provider-reported balance per account plus the
  rollup, so an asset-capturing consumer needs one registry row, not
  per-provider glue;
- **YTD interest (1099-INT raw material)** — `interest list` and
  `interest ytd`;
- **transactions for spending/burn-rate ingestion** — `transactions list
  --since --until`;
- **statements and tax forms** — `documents list` / `documents download`
  (the `documents/v1` profile);
- **the same reads for Claude** — `sfi mcp` (see "MCP tools" below).

Conforms to `piekstra-cli/1` (see `~/Dev/cli-common/DESIGN.md` and
`conformance.md`). Shared behavior comes from the `pk-cli-*` crates pinned to
tag **v0.27.0** — reuse before writing (dates, output, `RangeArgs`, `Paged`,
keychain, config, self-update, the `documents/v1` DTOs and its
`verify`/`fs_safe` download hygiene, and `pk-cli-browser` for the browser
sign-in).

## Build / test / lint

```console
$ make verify     # fmt-check + clippy -D warnings + test + smoke — the CI gate
$ make dev        # debug build, re-signed for stable keychain grants
$ make install    # installs to ~/.cargo/bin and re-signs
```

Tests are **fully offline**: no network, no keychain, no credentials. Keep
them that way (see "Auth: browser cookie harvest (the supported path)" below).

## Layout

| Path | Owns |
| --- | --- |
| `src/main.rs` | clap tree, dispatch, exit-code mapping |
| `src/config.rs` | non-secret settings (username, default account) |
| `src/client.rs` | HTTP, the login/MFA dance, session cookies, downloads |
| `src/browser.rs` | `auth login --browser` on `pk-cli-browser`: what is read, the confirm read, the GraphQL recipe |
| `CHANGELOG.md` | what each release changed |
| `src/commands/*.rs` | one module per command group |
| `src/mcp.rs` | `sfi mcp`: the MCP tools over a `Source` seam |
| `packaging/mcpb/` | the Claude Desktop extension manifest |
| `tests/cli_surface.rs` | black-box `assert_cmd` surface tests |
| `tests/fixture_shapes.rs` | contract tests over `tests/fixtures/` |
| `tests/mcp_stdio.rs`, `tests/packaging.rs` | `sfi mcp` over stdio; the `.mcpb` manifest against the binary |
| `docs/api.md` | the API as we understand it, **and the traps** |

## Non-negotiables

- **Read-only, enforced in code.** No transfers, no payments, no settings
  changes. `sfi api` accepts `GET` only and exits 2 otherwise. If a write is
  ever added, the README's read-only claim changes in the *same* commit.
- **`--json` on every command**, exactly one DTO per invocation, `schema`
  tagged. Human output to stdout, diagnostics to stderr.
- **Exit codes**: 0 ok · 2 usage · 3 auth · 4 not found · 5 upstream ·
  6 confirmation required.
- **Validate args before touching keychain or network**, so `--help` and bad
  input never prompt, hang, or hit the provider.
- **Secrets only** from the OS keychain (`piekstra.sfi`), stdin, or a named
  env var — never argv, never a file, never a log.
- **ISO `YYYY-MM-DD`** on every date flag.

## Honesty rules (this is an unofficial API; it lies)

These are the ones that cost real debugging time elsewhere in the family:

- **Never report success from a status code alone.** A `200` carrying an HTML
  login page is an auth failure. Treat "HTML where JSON was expected" and
  "landed on a login URL" as `CliError::Auth`, not success.
- **A download is not a document until it matches its declared filetype.**
  `%PDF` magic for a PDF; none of the known failure shapes — a JSON error, an
  S3 XML error, HTML where it wasn't promised. Check before writing and
  before reporting bytes written: an expired pre-signed URL answers `200`
  with XML or HTML.
- **Chase the small anomaly.** A blank field in an otherwise-working response
  is usually the failure reporting itself.
- **One login attempt, then stop.** No retry loop around authentication ever.
  A loop against an MFA challenge is how a bank account gets locked.
- **Almost everything here is UNVERIFIED-LIVE.** SoFi's private API is only
  thinly community-documented, and no live capture session has confirmed the
  endpoint paths yet. `docs/api.md` labels every endpoint; when a live
  session verifies (or corrects) one, move the label and say how.

## Auth: browser cookie harvest (the supported path)

SoFi's login is Auth0 + Cloudflare + ThreatMetrix + SMS MFA, and the plausible
JSON login endpoint **404s live** (confirmed 2026-08-24, docs/api.md §2.6).
There is nothing to script. So `sfi auth login --browser` opens a real Chrome,
the **owner** signs in by hand, and the CLI reads the session cookies over the
DevTools protocol and stores them in the keychain (`session`).

- **Owner-present only, and a live login costs an SMS code.** Never run
  `auth login --browser` from automation; it needs a human at the keyboard.
- **A login flag the browser branch does not read conflicts with `--browser`**,
  so it is refused (exit 2), not ignored. The test
  `every_login_flag_the_browser_branch_does_not_read_is_refused` holds a new flag
  to this.
- **The mechanism is cli-common's `pk-cli-browser`; `src/browser.rs` is only
  SoFi's side of it.** The crate owns finding and launching Chrome
  (`SFI_CHROME`), the kept `0700` profile, Ctrl-C, closing the tab and the
  teardown. `browser_capture` says what to read; the confirm hook, the
  validation read and the recipe derivation are sfi's. Don't re-embed
  DevTools code here: a capture the crate can't express is a cli-common
  change.
- **The profile is kept between sign-ins**, at `~/Library/Application
  Support/piekstra.sfi/browser-profile` on macOS
  (`$XDG_DATA_HOME/piekstra.sfi/browser-profile`, or under `~/.local/share`, on
  Linux), so SoFi's remembered device and its session carry over and a later
  `--browser` often needs no input. `--fresh-profile` runs one sign-in in a
  scratch profile and leaves the kept one alone. `auth logout` removes the kept
  profile as its last step, through `run_logout`, whose removal is a closure:
  the binary binds `forget_profile(BIN)`, tests bind
  `forget_profile_in(&temp_dir, BIN)`. A test never reaches the real profile. A
  service `SFI_KEYCHAIN_SERVICE` names is a test namespace that must not read or
  change the real profile or config: `auth logout` skips the removal and says
  so, `auth login --browser` takes a scratch profile and says so
  (`scratch_profile_choice`), neither writes the real config unless `--config`
  names a file (`keeps_real_config`), and `auth status` leaves `browser_profile`
  out and says so. The config is loaded only in the commands that use it, so
  logout runs on a file that can't be parsed. It is a full Chrome profile:
  history with full URLs, the HTTP cache and site storage sit outside Chrome's
  cookie encryption, and on Linux with no desktop keyring so does the session
  cookie (SECURITY.md). A failed sign-in leaves it. The whole sign-in runs
  inside `noting_kept_profile`, which adds the note to every failure except the
  refusals before Chrome uses the profile. Every logout step is attempted, and a
  failed logout's error says what was cleared and what remains. `auth status`
  reports it through `browser_profile_status`, a seam the tests fill with
  `profile_exists_in`: whether a profile is kept, not whether it is signed in.
  sfi must not work out the path itself. `clear_site_storage` stays off, since
  the capture reads only cookies and no token bundle is kept in site storage.
- The capture reads only `www.sofi.com` pages (never the Auth0 login host),
  gates on the `SOFI` bearer cookie, and reads the whole `sofi.com` jar (both
  `login.sofi.com` and `www.sofi.com` — docs/api.md §2.5);
  `Session::from_pairs` keeps the four session cookies. Before the tab closes
  it validates against a **swappable** read (`SFI_VALIDATE_PATH`, default the
  accounts collection). In a scratch profile a 404 there doesn't block the
  login, since the read endpoints are themselves unverified. In the kept profile
  a read that can't decide (`pk_cli_http::inconclusive`, no answer, an edge
  block's page, a 2xx that is empty or not JSON) is `Confirm::Undecided`, so nothing
  unverified is stored from a `SOFI` cookie that may be left from an earlier
  sign-in, and a finished sign-in is not lost, since that cookie does not survive
  the stop. The crate does the backoff, the status line and exit 5. A 2xx alone is
  not acceptance: `shows_an_account` tests the field's value, and a parseable answer
  without one is `NotYet`. `Confirm::Fail` stays for what no later poll can change:
  a 404 there in the kept profile, and a client that can't be built. An unverified
  session from a scratch profile warns even under `-q`, and `refuse_replacing` keeps
  it from replacing a stored one that works (exit 2) or can't be checked (exit 5)
  without `--overwrite`. `ReadError` types each kind of answer, so nothing matches
  on wording, and a reason holds fixed parts only. The capture reads no
  `localStorage`; keep it that way, or a stale token bundle in the kept profile becomes readable on page load.
- The GraphQL header recipe comes from the first `/bff/graphql` request a
  `www.sofi.com` page makes; the tab is held open up to 25 s for one. Only
  header names and the CSRF cookie's name are stored.
- **SoFi's side is tested offline on hand-built captures.** `pk-cli-browser`'s
  `test-util` feature (a `[dev-dependencies]` entry at the same tag, so the
  shipped binary is built without it) gives `Captured::for_test`,
  `JarCookie::for_test`, `CapturedRequest::for_test` and
  `forget_profile_in`. The confirm hook is
  `confirm_with(candidate, quiet, path, client)`, with `confirm` passing
  `&validation_path()` and `Sofi::new`; a test passes a literal path and
  `|| Sofi::with_base(<loopback>)`, so every `Confirm` answer is exercised
  without SoFi and without reading the environment. Keep both pins on one
  tag.
- **A test never depends on an ambient env var.** Code that reads one splits
  into a pure function taking the value (`validation_path_from`) and a thin
  caller that fills it from the environment; tests call the pure one. The
  only env var a test reads is `SFI_TEST_KEYCHAIN`, the deliberate opt-in
  for the keychain surface tests. Nothing mutates the process environment:
  `clippy.toml` disallows `std::env::set_var` and `std::env::remove_var`, so
  `make lint` fails on a new use. A subprocess test may pass `.env(..)` to
  the child it spawns.
- The **retained password/`--code` flow is dead-live** — kept only for the day
  a scriptable endpoint exists. Don't try to make it work; use `--browser`.
- **Read-endpoint status:** accounts, net-worth, `interest ytd`, and
  `documents list` are **LIVE-VERIFIED** (2026-08-24); **transactions
  (`/bff/graphql`) answer live** (2026-08-31, after the header-recipe fix for
  the first session's 403). Its `createdDate.mmddyyyy` is **unseparated
  `MMDDYYYY`** — a slashed-only parser left every live row undated until
  2026-10-01. `documents download` is unprobed. When a session verifies (or corrects) an endpoint, move its
  label in docs/api.md and say how.
- **The APY string keeps its trailing `%`** (`"3.10%"`) — pass `formattedApy`
  through verbatim; never strip or reformat it (a fixture test pins this).
- **`interest ytd` is an estimate, not a 1099-INT number** — it reports the
  provider's `estimatedInterestThisYear` (`source: provider_estimate`), and
  whether that is YTD-so-far or a full-year projection is unresolved
  (docs/api.md §3.2/§7); the transactions feed will settle it.
- **Ask before spending a live login.** Prefer the offline fixtures.

## MCP tools

`sfi mcp` (src/mcp.rs) serves four read-only tools under cli-common's MCP
profile (DESIGN.md §1.9): `sofi_balances` (the `net-worth` reading),
`sofi_transactions` (settled transactions over a date range),
`sofi_interest` (the `interest ytd` figures, by account) and
`sofi_documents` (statements, listed, never downloaded). They read through
the `Source` trait; `LiveSource` wraps the same `Ctx` and fetchers the
commands use (`accounts::fetch`, `transactions::fetch_entries`,
`documents::fetch_rows`), one read at a time, since `Sofi` paces its
requests and is not `Sync`. The tools never sign in: an auth error asks the
user to run `sfi auth login --browser` in a terminal (the profile's standard
remedy names plain `auth login`, whose endpoint is dead).

- Tests: `src/mcp/tests.rs` runs every tool in process over the fixtures
  through a fixture `Source` and cli-common's conformance helper;
  `tests/mcp_stdio.rs` drives the binary over stdio without reading the
  keychain; `tests/packaging.rs` holds `packaging/mcpb/manifest.json` to the
  binary.
- Budget: the definitions stay under 8,000 characters together
  (`the_definitions_stay_small` prints each size). Shorten a description
  before adding a field.
- To see the sign-in error from the installed binary without opening the
  real session, set `SFI_KEYCHAIN_SERVICE` to a service that holds nothing:
  a missing keychain item is read without a prompt and fails as "not logged
  in". The variable only renames which entry is read; it never carries a
  session.

## Releases

Bump `Cargo.toml`, `Cargo.lock` and `packaging/mcpb/manifest.json` together and
add a `CHANGELOG.md` section. Push a `v*` tag whose version matches `Cargo.toml` and
`packaging/mcpb/manifest.json` (`.github/workflows/release.yml` refuses a
mismatch). The workflow builds `sfi-<target>.tar.gz` for both Apple targets,
`x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` (the names
`self-update` expects), plus `sfi-<version>.mcpb`, the Claude Desktop
extension, which takes no settings and reads the keychain session. A pull
request that changes the workflow, `packaging/`, `Cargo.toml` or
`Cargo.lock` runs the same builds as a dry run.

## Fixtures

`tests/fixtures/` is **synthetic** — every value is a dummy, and no captured
file is ever committed. Structure provenance is recorded in
`tests/fixtures/README.md` with citations to the community sources each file
models. If you ever capture a real response to check a shape, scrub it before
it reaches the working tree and never commit the raw file (a statement link
may be a live pre-signed credential). A test enforces the scrubbing policy
positively: identity-bearing fields must match a known dummy shape.

## Definition of done

`make verify` green, CI green (or mirrored locally when Actions minutes are
capped), `docs/api.md` matching reality (including what is still
**UNVERIFIED-LIVE**), `--json` and human output in sync, and no secrets or
personal data anywhere in the diff — fixtures included.
