# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[security advisories](https://github.com/piekstra/sofi-cli/security/advisories/new)
rather than a public issue.

## Threat model

`sfi` authenticates to SoFi's **unofficial, community-documented** private
API on behalf of one household and reads their primary cash accounts. The
things worth protecting, all stored in the OS keychain under service
`piekstra.sfi`:

- **The account password** (`password`). Read at point of use, never logged,
  never placed on argv, never written to disk.
- **The cached session** (`session`) — the cookie set the login flow
  produced. It is a bearer credential: anyone holding it can read the
  accounts until it expires.
- **The device id** (`device`). Not a secret on its own, but it is the value
  that carries *device trust* — a third party holding both it and the
  password may be able to skip the MFA challenge that would otherwise stop
  them.
- **A parked mid-MFA login** (`pending`). Short-lived and single-use:
  deleted on the next `--code` attempt whether it succeeds or fails.

SoFi's session cookies also sit in the browser profile a `--browser` sign-in
keeps (below), outside the keychain.

Additionally, **statement links returned by the portal may be pre-signed**
and grant access to a bank statement or tax form without a session. Never
paste one into an issue, a log, or a commit.

**The browser login (`--browser`) opens a short-lived Chrome debug port.** `sfi
auth login --browser` launches Chrome with `--remote-debugging-port` and the
profile `sfi` keeps, through cli-common's `pk-cli-browser`, to read the session
cookies over the DevTools protocol. That debug port has **no authentication of
its own** — anything that can reach `127.0.0.1:<port>` (or read the profile's
`DevToolsActivePort`) could read the live `SOFI` cookie during the login window.
The `www.sofi.com` tab is closed as soon as the session is read, and Chrome is
stopped on every exit path, including Ctrl-C (a kept profile is asked to quit
first, so a cookie set just before the close is on disk for the next sign-in); a
second Ctrl-C force-quits it. The port exists only while you are signing in.

**The browser profile stays on disk between sign-ins**, so SoFi remembers the
device. It lives at `~/Library/Application Support/piekstra.sfi/browser-profile`
on macOS (`$XDG_DATA_HOME/piekstra.sfi/browser-profile`, or under
`~/.local/share`, on Linux). It is a full Chrome profile, so it holds more than
the session:

- **Cookies**, SoFi's session among them. Chrome encrypts these at rest, on macOS
  with the "Chrome Safe Storage" key in the login keychain and on Linux with the
  desktop keyring. **On Linux with no desktop keyring it falls back to a fixed,
  publicly known key**, so there the session cookie is effectively unencrypted and
  `0700` is its only protection. Use `--fresh-profile` on such a machine.
- **Browsing history with full URLs including query strings, the HTTP cache and
  site storage** (`localStorage`, IndexedDB). Chrome's cookie encryption does not
  cover these, and the directory's `0700` mode is their only protection. The
  cache can hold what SoFi's pages loaded during a sign-in.
- **It sits where ordinary backups look.** Time Machine and home-directory
  backups usually include this directory, so a copy can outlive the profile, and
  `sfi auth logout` cannot reach a backup. Exclude the directory from backups, or
  use `--fresh-profile`, if that matters to you.

So:

- The profile is created `0700`, and a launch is refused when it is a symlink,
  is not your user's or is not `0700`.
- One sign-in uses it at a time. A second, or a launch while a Chrome still runs
  in it, is refused (exit 1).
- `sfi auth logout` removes it, and refuses while it is in use or when it is a
  symlink or another user's. Every step of a logout is attempted, so a refusal
  or a failed keychain or config step leaves the rest done. The error says what
  was cleared and what remains, names the path and says how to finish, with the
  first failure's exit code. A logout does not parse the config, so a file that
  can't be parsed stops nothing, and `--forget` overwrites it.
- A sign-in that fails once Chrome may have used it leaves it in place, possibly
  signed in: a timeout, a closed window, Ctrl-C, a validation read that ends the
  wait, a keychain write that fails after the capture. The error says so and
  names `sfi auth logout`, which removes it and clears the stored session too. A
  second Ctrl-C force-quits with no message. A launch refused before Chrome uses
  it (no Chrome, a profile in use or needing repair) says nothing about it,
  since `auth logout` would refuse the same profile. `sfi auth status` reports
  whether one is kept, not whether it is signed in.
- A `SOFI` cookie left in it from an earlier sign-in is not trusted alone. In the
  kept profile only a validation read showing an account accepts a session, and a 2xx alone does not. A
  read that can't decide (a 429, a 5xx, no answer, an edge block's page, a 2xx that
  is empty or not JSON) keeps the tab and the jar, and the crate asks again after a
  backoff, since the cookie does not survive the stop and ending the wait could lose
  a finished sign-in. Ctrl-C ends it. A wait that runs out on it is exit 5 and stores
  nothing. Only a 404 ends the wait early. Only `--fresh-profile`, whose profile
  started empty, accepts on the cookie when that read can't decide. It warns even
  under `-q`, and that session never replaces a stored one that works (exit 2) or
  could not be checked (exit 5) without `--overwrite`.
- `--fresh-profile` runs one sign-in in a scratch profile instead, created
  `0700`, exclusively, under an unpredictable name in the temp dir, and removed
  when the window closes. If it cannot be removed, `sfi` prints a warning naming
  it, even with `-q`, because it may hold the session.
- Windows has no kept profile: every sign-in there uses a scratch one.

The capture only reads pages on `www.sofi.com`; the Auth0 login page, where
the password and the code are typed, is never attached to. To learn the app's
GraphQL header recipe it watches those pages' network requests without request
bodies, and keeps only header names and the name of the cookie the CSRF header
is copied from. No header value is stored.

## The MCP server

`sfi mcp` serves read-only tools to an MCP client (Claude Code, Claude
Desktop) over stdio, on this machine only; it opens no port. It uses the
session already in the keychain, exactly as the commands do, and never signs
in: a missing or expired session is an error asking the user to run
`sfi auth login --browser` in a terminal. No tool downloads a statement or
returns a statement link. The Claude Desktop extension (`.mcpb`) takes no
settings and so holds no credential of its own; on macOS its bundled binary
needs the user's approval, once, to read the `piekstra.sfi` keychain item.

`SFI_KEYCHAIN_SERVICE` renames the keychain service read and written, for tests
and for checking the error paths against an empty service. It carries no secret.
A service it names is a test namespace, and must not read or change the real
kept browser profile or the real config. While it names one, `sfi auth logout`
clears that service, leaves the real profile in place and says so, `sfi auth
login --browser` uses a scratch profile, as with `--fresh-profile`, and says so
in one line on stderr, neither `auth logout --forget` nor a sign-in writes the
real config: each says it was left, and `sfi auth status` reads nothing about
the real profile, leaves `browser_profile` out and says so. A `--config` you
name is still written. A blank value names no service.

## What this tool does not do

- **It never moves money, pays a bill, or changes account settings.** There
  is no transfer, payment, or settings code path in the binary. `sfi api`
  refuses any method other than `GET` (exit `2`).
- It talks only to SoFi's own hosts and the pre-signed document hosts the
  portal returns. No telemetry, no third-party services.
- It hardcodes no secrets. `gitleaks` runs in CI over the full history.

## Unofficial-API risk

SoFi publishes no public API for member accounts and its terms discourage
automated access. Using this tool carries provider-side risk that a supported
API would not: rate limiting, MFA loops, or account restriction.
`docs/api.md` records the honest failure modes. Two rules follow from that
and are enforced in code:

- **One login attempt, then stop.** There is no retry loop around
  authentication, because a loop against an MFA challenge is how an account
  gets locked.
- **Never claim success without positive confirmation.** A `200` carrying an
  HTML login page is an auth failure, and a "downloaded" file that does not
  begin with `%PDF` is not a statement.

## Handling credentials safely

Prefer piping from a password manager over typing:

```console
$ op read 'op://Private/sofi/password' \
    | sfi auth set-credential --stdin --overwrite
```

`sfi auth logout --forget` removes the password, session, device id, and any
parked login from the keychain. Plain `sfi auth logout` removes the session and
any parked login. Both also remove the kept browser profile.
