# Changelog

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
