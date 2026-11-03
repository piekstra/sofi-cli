# Changelog

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
