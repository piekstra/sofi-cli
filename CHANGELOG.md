# Changelog

## v0.3.3 — 2026-11-03

Built on cli-common v0.20.0.

- A `sfi auth login --browser` that runs out of time before you finish signing in
  now says what the validation read was told, where it used to say only "answered
  as signed out". Still exit 3.
- A read that can't decide no longer ends a kept-profile sign-in or, for an edge
  block, reads as a dead session. That is a 429, a 5xx, a dropped connection, an
  edge block's page (an HTML 403, 429 or 5xx, or a page titled as a challenge), or a
  2xx that is empty or not JSON. The window stays open, since the session cookie
  does not survive the stop, and cli-common asks again after a backoff of 6 s,
  doubling to 60 s, or longer if SoFi's `Retry-After` asks. Its first such answer
  prints one status line, unless `-q`, saying Ctrl-C ends the wait. **A wait that
  runs out on it is now exit 5, not exit 3**, because signing in again fixes
  nothing. A 404 there still ends the sign-in at once, since no later poll can
  change it.
- A 2xx alone no longer accepts a session. The accounts read must show a non-empty
  `accounts` list or `partyId`, and a parseable answer without one keeps the wait
  going, in both profiles. A path `SFI_VALIDATE_PATH` names has no known shape, so
  any non-empty object or array still counts there.
- A `--fresh-profile` sign-in stored on a read that can't decide now warns even
  under `-q`, naming the cause and `sfi auth login --browser --overwrite`. For an
  edge block it says first that a new sign-in may not clear it, and to wait or try
  another network. Without `--overwrite` it no longer replaces a stored session that
  works (exit 2) or that a read could not check, a plain 403 included (exit 5). The
  stored one stays and nothing is stored.
- `sfi auth login --json` used to run and print nothing on stdout. It now prints
  `auth-login/v1` on every path that stores a session, with `verified` always a
  boolean: `true` when a read showed an account, `false` otherwise.
- `--browser --overwrite` parses again, since v0.3.2 refused it, and now has the
  effect above. `--overwrite` alone still does nothing.
- Outside a sign-in, an HTML page on a 403, 429 or 5xx, or a page titled as a
  challenge, names itself as a possible bot check or edge block: a new sign-in may
  not clear it, so wait or try another network. A 403 without an HTML page names
  both causes. An HTML 429 or 5xx used to read as a lapsed session or a block at
  exit 3, and is now exit 5, as any other 429 or 5xx is. The GraphQL BFF follows the
  same rule. Other exit codes are unchanged. The text holds a status and a
  URL without its query, never a cookie value or the page.
- `sfi auth login --help` no longer offers `--no-verify`, which no login path
  reads. It still parses without `--browser`, so a script that passes it does not
  break.

## v0.3.2 — 2026-11-03

`sfi auth login --browser` now refuses every login flag it does not read, with
exit 2 and the flag named on stderr. Each of these used to parse and be ignored.
A script that passes one beside `--browser` must drop it:

- `--stdin` and `--from-env`: the password on stdin or in the variable was never
  read.
- `--no-verify`, `--overwrite`, `--non-interactive` and `--channel`: the sign-in
  ran the same with or without them.

`--fresh-profile` stays allowed. These flags still parse without `--browser`.

## v0.3.1 — 2026-11-03

Moves to cli-common v0.19.0. The minimum Rust version is now 1.89.

- A sign-in in the kept profile now asks Chrome to quit before stopping it, so a
  remember-this-device cookie set just before the window closes is on disk for
  the next sign-in. Measured by cli-common in headless Chrome only: on v0.16.0 a
  cookie written just before the close survived 6 of 40 runs, and on v0.19.0 40
  of 40. A stuck Chrome can hold `sfi` for up to 11 s, up from 6 s.
- `sfi auth status` reports `browser_profile` within `auth-status/v1`: whether a
  profile is kept, not whether it is signed in. A profile that needs repair is a
  warning on stderr and leaves the field out.
- While `SFI_KEYCHAIN_SERVICE` names a service, `sfi auth status` reads nothing
  about the real profile, leaves `browser_profile` out and says so on stderr.
- `sfi auth login --fresh-profile` without `--browser` is a usage error (exit 2)
  whichever other flag is beside it. It used to parse beside `--code` or
  `--username`, and the flag was ignored.

## v0.3.0 — 2026-11-03

Moves to cli-common v0.16.0. A browser sign-in now runs in a profile `sfi`
keeps, where it used to run in a scratch profile deleted after every sign-in.

- `sfi auth login --browser` keeps its Chrome profile on disk, owner-only
  (`0700`), at `~/Library/Application Support/piekstra.sfi/browser-profile` on
  macOS and `$XDG_DATA_HOME/piekstra.sfi/browser-profile` (or under
  `~/.local/share`) on Linux, so SoFi's own cookies carry over and later
  sign-ins need less input. Windows still uses a scratch profile every time.
- `sfi auth login --browser --fresh-profile` runs one sign-in in a scratch
  profile, and leaves the kept one alone.
- `sfi auth logout` also removes the kept profile, as its last step. It exits 1
  with the crate's message while a sign-in or a Chrome is using the profile, or
  when the path is a symlink or another user's; the keychain items are cleared
  by then, and the error and `auth logout --help` say so.
- `sfi auth logout` attempts every step even when one fails or the config can't
  be parsed, and says what was cleared and what remains, with the first
  failure's exit code. `--forget` clears a config that can't be parsed.
- While `SFI_KEYCHAIN_SERVICE` names a service, `sfi auth logout` leaves the
  real profile in place, `sfi auth login --browser` uses a scratch profile, and
  neither writes the real config, and each says so.
- A `--browser` failure once Chrome may have used the kept profile says the
  profile stays and that `sfi auth logout` removes it.
- In the kept profile, an inconclusive validation read no longer accepts the
  `SOFI` cookie, which may be left from an earlier sign-in, and a 200 with no data
  no longer verifies a session. The first 429, 5xx, 404, transport failure or empty
  answer ends the sign-in (exit 5) and says to retry or use
  `--fresh-profile`, which keeps the old behaviour.
- SECURITY.md and the README state what the kept profile holds: it is a full
  Chrome profile, with history, HTTP cache and site storage outside Chrome's
  cookie encryption, `0700` as their only protection, in a directory backups
  usually include. On Linux with no desktop keyring the session cookie has only
  `0700` too.
