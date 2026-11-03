# The SoFi API, as `sfi` uses it

SoFi publishes **no public API for member accounts**. Everything in this
document comes from community reverse-engineering — chiefly two
browser-extension projects that piggyback on an already-authenticated browser
session — and **none of it has been confirmed against the live service by this
project.** Every endpoint below is therefore labelled **UNVERIFIED-LIVE**
until an owner-present live capture confirms (or corrects) it. Read §6 for the
live-smoke plan and §7 for what is deferred.

The convention this file follows (the family's `api.md` discipline):

- Every endpoint carries a **status label** and its **community source**.
- **A status code is never success.** SoFi's stack answers rejected/expired
  requests with an HTML login page (or a Cloudflare interstitial) under a
  `200`, and its GraphQL BFF returns errors in a `200` body. The client treats
  HTML-where-JSON-was-expected and a GraphQL `errors` array as auth failures.
- What is still unverified is said so, in the endpoint and in the code.

## 1. Headline findings

- **Two API styles.** SoFi Bank is a **GraphQL BFF** (`POST /bff/graphql`);
  the rest (accounts, statements, profile) are **private REST** endpoints
  under `https://www.sofi.com`. SoFi's own engineering blog confirms the split
  ("REST endpoints in Invest … a GraphQL-based BFF in Bank"). The `.../public/...`
  in the REST paths is a misnomer — they are session-gated, not public.
- **Login is the hard part — and the modeled endpoint is dead.** The web login
  runs through **Auth0 Universal Login on `login.sofi.com`**, fronted by
  **Cloudflare bot protection** and **ThreatMetrix device fingerprinting**,
  with **SMS OTP** (`twoFactorType: "SMSV1"`). The password-POST flow this repo
  first shipped (`POST /login-service/v1/login`) was **probed live on
  2026-08-24 and answered HTTP 404 — it does not exist.** No community project
  scripts SoFi's login; they all reuse cookies from a human browser login. So
  `sfi` logs in the same way: **`sfi auth login --browser`** opens a real
  Chrome window, the owner signs in, and the CLI reads the session cookies
  over the Chrome DevTools Protocol (§2).
- **Auth is cookie-based.** A logged-in session carries `SOFI`,
  `SOFI_SESSION`, `SOFI_LOGIN`, and `SOFI_R_CSRF_TOKEN` cookies. GET reads need
  only the cookies; the GraphQL POST additionally echoes the CSRF cookie in a
  `csrf-token` header.

## 2. Authentication — browser cookie harvest (supported)

### 2.1 The reality

Community projects (see Sources) **never** POST credentials to SoFi. They open
`https://www.sofi.com/my/banking/accounts/` in the user's real browser, let
the human clear Cloudflare + Auth0 + the SMS code, then read the session
cookies and call the private APIs. The login itself is Auth0-hosted
(`login.sofi.com/u/login`, an opaque `state` token, an Auth0 `client_id`),
which is an HTML flow, not a JSON API. **`POST /login-service/v1/login`, the
plausible JSON login endpoint this repo first modeled, returns HTTP 404 live
(2026-08-24) — it does not exist** (§2.6).

### 2.2 `sfi auth login --browser` — the supported path — **LIVE-VERIFIED 2026-08-24**

`--browser` reads only `--fresh-profile` and `--overwrite`. Beside `--stdin`,
`--from-env`, `--code`, `--username`, `--no-verify`, `--non-interactive` or
`--channel` it is exit 2 from clap, before anything reads the keychain or the
network or opens Chrome.

Confirmed live: captured the session on the first try, the validation read
answered ("2 accounts visible"). The mechanism is cli-common's
`pk-cli-browser` (its DESIGN.md §2.2), the family's shared browser sign-in;
`src/browser.rs` says what to read (`browser_capture`) and confirms it:

1. Launch a real Chrome — `SFI_CHROME` overrides the binary search — at
   `https://login.sofi.com/u/login`, with `--remote-debugging-port=0`, the kept
   `0700` profile (below) and first-run suppression. No automation flags, so
   `navigator.webdriver` is `false` and the page looks like an ordinary
   browser to Cloudflare/ThreatMetrix.
2. The **owner signs in by hand** (password and the texted code). The CLI
   never drives the page, and never attaches to the `login.sofi.com` page at
   all, so the anti-bot stack sees a real human.
3. Every ~3s the crate lists the pages and, once one is open on
   `www.sofi.com` (the app, where Auth0 redirects after sign-in), reads the
   browser's cookies with one `Storage.getCookies`. That call returns
   **HttpOnly** cookies (unlike page JS) and covers **every origin** the
   profile holds, so the `sofi.com` jar includes both `login.sofi.com` and
   `www.sofi.com` (§2.5). The `SOFI` bearer cookie (app origin, set only
   post-login) is the "signed in" gate; `Session::from_pairs` keeps the four
   session cookies (§2.4) and drops the rest.
4. From the moment a `www.sofi.com` page opens, the crate watches that page's
   requests for the app's first `/bff/graphql` request (§3.4). Once `SOFI` is
   set, if none has come yet, the tab is held open up to **25 s** for one.
   Only the header **names** and the name of the cookie the CSRF header is
   copied from are kept (`GraphqlRecipe`); with no request, the client uses
   the modeled header defaults and says so.
5. Before the tab closes, the session is validated with a mild read (§2.5).
   On success the tab closes, Chrome quits, and the session goes to the
   keychain (`session`). A refused answer keeps the tab open and asks again on
   the next poll. A read that can't decide (§2.5) keeps the tab and the jar in
   the kept profile, and the crate asks again after a backoff of 6 s, doubling
   to 60 s, or longer if SoFi's `Retry-After` asks, up to five minutes. Its first
   such answer prints one status line, unless `-q`, saying Ctrl-C ends the wait.
   The wait lasts up to **10 minutes**. If it runs out with the read still unable
   to decide, that is exit 5: signing in again fixes nothing, nothing is stored,
   and the cookie is gone, so the sign-in may have to be repeated. If it runs out
   before the owner finishes signing in, that is exit 3, and the error says what
   was missing: no `www.sofi.com` page, the `SOFI` cookie, or what the validation
   read was told, and, once the jar was read, its cookie names (never a value).
   A reason holds a status and a URL without its query, never a cookie value or
   the page. Closing the window is exit 3 too; Ctrl-C cancels (exit 1).

**The kept profile.** Chrome runs in `<data dir>/piekstra.sfi/browser-profile`,
which stays on disk, so SoFi's own cookies (its remembered device, the Auth0
session, Cloudflare's clearance) carry over and a later `--browser` should need
less input. **UNVERIFIED-LIVE:** no second sign-in has run in a kept profile
yet, so how far SoFi lets one go (and whether `/u/login` forwards a signed-in
browser to `www.sofi.com`) is unknown. `--fresh-profile` runs one sign-in in a
scratch profile, and `sfi auth logout` removes the kept one. `sfi auth status`
reports `browser_profile`: whether one is kept, not whether it is signed in, and
nothing while `SFI_KEYCHAIN_SERVICE` names a service. It is a full Chrome
profile: SECURITY.md lists what it holds. A sign-in that fails once Chrome may
have used it leaves it in place, and its error says so and names `sfi auth
logout`. A launch refused before that says nothing about it.

**Trust boundary:** the CDP debug port has no auth of its own, so the profile is
owner-only: `0700`, and refused when it is a symlink, another user's or any
other mode (anything that can read `DevToolsActivePort` could read the live
`SOFI` cookie during the login window). The tab closes the moment the session is
read, and Chrome is stopped on every exit path, including Ctrl-C (a kept
profile's is asked to quit first, so a cookie set just before the close is on
disk). A scratch profile is created exclusively under an unpredictable name and
removed with it.

### 2.3 The retained password/`--code` flow — DEAD-LIVE

`sfi auth login` (no `--browser`) still contains the family portal-auth shape:
a password POST to `POST /login-service/v1/login`, an MFA challenge parked in
the keychain (`pending`), and a `sfi auth login --code <CODE>` resume against
`POST /login-service/v1/login/verify`. **Both endpoints 404 live (2026-08-24),
so this path cannot succeed today.** It is kept — with `client::interpret_login`
still pure and unit-tested — only so that if SoFi ever exposes a scriptable
login, the mechanics are already in place; `--browser` is the path to use.
`deviceId` is still persisted (keychain `device`) for that eventuality.

### 2.4 Cookies

| Cookie | Role |
|---|---|
| `SOFI` | Encrypted auth token, HttpOnly — the real bearer credential (app origin `www.sofi.com`). |
| `SOFI_SESSION` | HttpOnly session id; embeds `TMX_SESSION` (ThreatMetrix) + `fpSessionId`. |
| `SOFI_LOGIN` | `1` when logged in (a flag, not a credential). |
| `SOFI_R_CSRF_TOKEN` | Readable; doubles as the CSRF token for GraphQL POSTs. |

`sfi` stores the joined `Cookie` header and the CSRF value in the keychain
(`session`). Source: `lijunle/bank-statement-downloader` `analyze/sofi.md`.

### 2.5 Two domains, and a swappable validation read

**Two origins hold cookies.** `login.sofi.com` carries the Auth0 login session
(an `auth0`/`session`-style cookie); `www.sofi.com` carries the app's
`SOFI`/`SOFI_SESSION`/`SOFI_R_CSRF_TOKEN`. The browser capture reads the
**whole** `sofi.com` jar (every cookie the browser would send to `sofi.com` or
a host under it, matched label for label, so `notsofi.com` and
`sofi.com.evil.example` never count), so whichever of the two domains a session
cookie lives on, it is read. **The client keeps and sends only the four session
cookies** of §2.4 (`SOFI`, `SOFI_SESSION`, `SOFI_LOGIN`, `SOFI_R_CSRF_TOKEN`),
as one `Cookie` header on every request to `www.sofi.com`; the Auth0 cookies
are dropped. *This is still partly modeled: exactly which cookie the app API
keys off is unconfirmed; `SOFI` presence is the signal used today.*

**Validation is swappable.** Before the tab closes, the session is confirmed
with a mild read — by default the accounts collection (§3.2), but that endpoint is
itself UNVERIFIED-LIVE, so the path is overridable with `SFI_VALIDATE_PATH`.
The classification (`browser::probe_outcome`, pure/tested):

- an answer showing an account → **accept**. On the accounts read that is the
  value of a field: a non-empty `accounts` list, or a non-empty `partyId` for a
  member with no account open. A path `SFI_VALIDATE_PATH` names has no known shape,
  so any non-empty object or array counts there;
- HTML that is not a challenge's / a login redirect / 401 / a 403 that is not an
  HTML page / another 4xx / a parseable answer with no account → **keep waiting**,
  in both profiles (`Confirm::NotYet`: not signed in yet, or a provider's refusal);
- a **read that can't decide**: a 429, a 5xx, no answer, an edge block's page (an
  HTML 403, 429 or 5xx, or a page titled as a challenge), or a 2xx that is empty or
  not JSON. A literal `null` reads as empty.
  - In the **kept profile** → `Confirm::Undecided`, with the provider's
    `Retry-After` when it sent one. The cookie may be left from an earlier sign-in,
    so it proves nothing without a working read, and it does not survive the stop,
    so ending the wait could lose a finished sign-in (cli-common DESIGN.md §2.2). A
    wait that runs out here is exit 5.
  - In a **scratch profile** (`--fresh-profile`) → **accept on the `SOFI` bearer
    cookie**, unverified. That profile started empty, so the cookie is this
    sign-in's.
- a **404** (the default endpoint doesn't exist) → in a **scratch profile**, accept
  on the cookie, unverified, so an unverified validation endpoint can't block a
  genuine login. After sign-in, live-probe the real read (`sfi api GET <path>`) and,
  if useful, set `SFI_VALIDATE_PATH`. In the **kept profile** → **end the wait**
  (exit 5), since no later poll can change it. The error names it and says to fix
  it, retry or use `--fresh-profile`.

`sfi auth login --json` prints `auth-login/v1` (`pk_cli_auth::AuthLogin`) on stdout,
on every path that stores a session, with `verified` always a boolean: `true` when a
read showed an account, `false` otherwise. On the browser path only a scratch-profile
acceptance gives `false`.

A session accepted unverified exits 0 and warns on stderr even under `-q`, naming
the cause and `sfi auth login --browser --overwrite`. When the cause is an edge block
the warning says first that a new sign-in may not clear it, because the block is on
the client rather than the session, and to wait or try another network. Without
`--overwrite` one read of the stored session decides whether it may be replaced:

| The stored session | What happens | Exit |
|---|---|---|
| None, or can't be parsed, has expired, or is refused (401, a login page, an answer with no account) | Replaced | 0 |
| Shows an account | Kept, nothing stored | 2 |
| Can't tell (a plain 403, an edge block, any read that can't decide, a 404) | Kept, nothing stored | 5 |

A verified session always replaces what is stored.

### 2.6 The live 404 — recorded 2026-08-24

`op item get … | sfi auth login --username <email> --stdin` →
`error: expected JSON but got an HTML page (HTTP 404)`. The modeled
`POST /login-service/v1/login` **does not exist**; the request hit SoFi's
front door and got the Auth0/marketing HTML 404. **Lesson:** for a provider
whose login sits behind Auth0 + Cloudflare + ThreatMetrix, do not model a JSON
login endpoint at all — go straight to a browser cookie harvest. The
community's uniform choice to reuse browser cookies was the tell; this CLI now
follows it (§2.2). The dead endpoints are labeled DEAD-LIVE in `client.rs`.

## 3. Endpoints

Base host: `https://www.sofi.com`.

### 3.1 Conventions

Every read presents the session cookies (`Cookie` header). REST reads (LIVE)
want `Accept: application/json` and nothing more. The GraphQL POST is stricter
(it 403'd live until these headers were added — §3.4): beyond the cookies it
sends `apollographql-client-name` (+`-version`), same-site `Origin`/`Referer`, and a CSRF header whose exact
name/source the browser login captures from the app itself. A REST collection
may be a bare array (statements) or a single object with an `accounts` array
(accounts) — there is no shared paging envelope. GraphQL paginates with an
`afterCursor` string.

### 3.2 Accounts — `GET /money/api/public/v2/accounts` — **LIVE-VERIFIED 2026-08-24**

The balances/APY/interest read, and the id source for the transactions query.
Confirmed live: two accounts (checking + savings), shape as modeled.

- **Request:** cookies only; `Accept: application/json`.
- **Response:** one object —
  `{ partyId, customerCombinedBalance{available, ledger}, accounts:[ … ] }`.
  Each account row:
  `{ id, type:"CHECKING"|"SAVING", number (masked), routingNumber, nickname,
  isFunded, balance{available, ledger}, combinedBalance{…}, owners[],
  formattedApy, formattedBaseApy, interestRate, formattedInterestRate,
  interestEffectiveDate, interestEarnedLifetime, estimatedInterestThisMonth,
  estimatedInterestThisYear, status:"ACTIVE", isRestricted, openDate,
  closeDate, partner, currency:"USD", isOpen }`.
- **Money and APY are strings** — balances two-decimal (`"2500.00"`, parsed to
  `Money`), and **the APY string INCLUDES the trailing `%`** (LIVE: savings
  `"3.10%"`, checking `"0.50%"`). `sfi` passes `formattedApy` through verbatim;
  a fixture test pins the trailing `%` so the spelling can't drift.
- Read by: `accounts list/get`, `net-worth` (sums `balance.available` — LIVE:
  correct savings + checking rollup), `interest ytd`
  (`estimatedInterestThisYear` / `interestEarnedLifetime`).
- **Trap:** `net-worth` refuses an account whose `balance.available` is
  missing rather than reporting `$0` — a blank balance is the failure
  reporting itself.
- **`interest ytd` ambiguity (open):** LIVE, `estimatedInterestThisYear` gave a
  plausible mid-year figure with `interestEarnedLifetime` ~5.6× it. Whether
  `estimatedInterestThisYear` is *year-to-date-so-far* or a *full-year
  projection* is **still unresolved** — the CLI reports it as-is with
  `source: "provider_estimate"`. The transactions feed (§3.4) settles it by
  summing actual interest payments; until then, treat the YTD figure as an
  estimate, not a 1099-INT number. (Tracked in §7.)
- Source: `lijunle/bank-statement-downloader`, `jjoelj/actual-bank-sync`;
  confirmed live 2026-08-24.

### 3.3 Documents (statements) — `GET /banking-service/api/public/v2/statements` — **LIVE-VERIFIED 2026-08-24** (list)

- **Request:** cookies only.
- **Response (LIVE):** a **bare JSON array** — 68 documents, monthly
  statements —
  `[{ statementDate:"YYYY-MM-DD", accountNumber:null,
  statementType:"COMBINED", documentId, description }]`. Statements are
  **combined** across accounts, so `accountNumber` is always `null`. `sfi
  documents list` maps these to `{id, date, name, category:"statement", file}`.
- **Download — still UNVERIFIED-LIVE:** `GET
  /banking-service/api/public/v2/statements/{documentId}` (shares no read path
  with `list`, so `list` being LIVE says nothing about it). Expected
  `Content-Type: application/pdf`; `sfi` verifies the `%PDF` magic before
  writing — an expired/again-login link answers `200` with HTML, which is never
  written, and HTML-where-a-PDF-was-promised is treated as an auth failure
  (exit 3). The `documentId` goes through `fs_safe` before it joins the URL
  path.
- Read by: `documents list` (LIVE) / `documents download` (unprobed)
  (`documents/v1` profile).
- Source: `lijunle/bank-statement-downloader` `bank/sofi.mjs`; list confirmed
  live 2026-08-24.

### 3.4 Transactions — `POST /bff/graphql` (operation `Transactions`) — **LIVE (read answers since 2026-08-31); date format corrected 2026-10-01**

SoFi Bank has **no REST transactions collection**; the web app reads them from
the GraphQL BFF.

**Live history.**

- 2026-08-24: **HTTP 403** with the harvested cookies — a header/CSRF issue,
  not an expired session. Fixed by sending `Origin`/`Referer`, an
  `apollographql-client-version`, and the CSRF header named by the recipe
  `sfi auth login --browser` captures from the app's own `/bff/graphql`
  request (`GraphqlRecipe`: header **names** and the CSRF cookie's name, never
  a value). A 403 still names which header inputs were sent, values redacted.
- 2026-08-31: the read **answered live** (the page-cap finding under
  Pagination below came from it).
- 2026-09-23: a live `interest list` capture (this feed, filtered) returned
  every row with **no `date`**. Cause: `createdDate.mmddyyyy` is
  **unseparated** — `MMDDYYYY`, eight digits, as the field name says and as
  the community client slices it (`sofiDateToISO`: `slice(0,2)`, `slice(2,4)`,
  `slice(4,8)`). The parser demanded `MM/DD/YYYY`, so nothing dated, and an
  undated row also slipped past every `--since`/`--until` check. Fixed
  2026-10-01: the parser reads the eight-digit form (the slashed form is still
  accepted), validates month and day, and `transactions list` and `interest
  list` warn on stderr (unless `--quiet`) when a row they report is still
  undated. The 2026-10-01 confirming read could not run:
  the stored session had lapsed (HTTP 401), and a new login needs the owner.
  The next owner-present `sfi transactions list --json` should show a `date`
  on every row; if one is missing, the stderr warning says so.

- **Request headers:** `content-type: application/json`,
  `apollographql-client-name: banking-accounts-ui`,
  `apollographql-client-version`, `origin`/`referer` (`https://www.sofi.com…`),
  `accept: application/json`, the CSRF header (recipe-driven name/source, else
  the modeled `csrf-token: <SOFI_R_CSRF_TOKEN>`), plus the session cookies.
- **Variables:** `{ accountIDs:[<id>], pageSize:500, afterCursor:<cursor|null>,
  filter:{ days:<int>, dateRange:null, searchText:null, amountFilter:null,
  transactionTypes:null } }`. The community code drives the lookback with
  `filter.days`, not `dateRange`; `sfi` converts `--since` to a day count
  (with a slack day or two) and enforces the exact `--since`/`--until` bounds
  client-side.
- **Response path:** `data.me.accounts[].transactions.list[]` →
  `{ cursor, transaction:{ id, amount{unformatted}, createdDate{mmddyyyy},
  description, displayType, expandedFields[]{title,value}, state } }`.
  `expandedFields` is requested as the community client requests it; the entry
  titled `Merchant` is surfaced as the DTO's `merchant` (absent when the row
  has none — a transfer, an interest credit).
- **The DTO (`transaction-list/v1`)** — each item:
  `{ id, date (ISO), description, amount (Money, signed: negative is money
  out), kind (displayType verbatim), merchant, state, account_id }`. Absent
  fields are omitted, never empty strings.
- **Only `state == "POSTED"` is settled.** Pending holds are excluded so a
  burn-rate figure isn't inflated by holds that may never clear.
- **Pagination:** pass the last entry's `cursor` as `afterCursor`. The server
  **caps a page at 100 rows** whatever `pageSize` asks (live 2026-08-31:
  `pageSize: 500` answered exactly 100 rows with a cursor), so only an empty
  page or a missing cursor ends the walk. `sfi` caps at 50 pages per account.
- **Traps:** a GraphQL error is a **`200` with an `errors` array** — the client
  checks for it and maps an `unauth`/`session` message to an auth failure. The
  `amount` and `createdDate` both **nest** (`unformatted`, `mmddyyyy`); the
  date is unseparated `MMDDYYYY` and is converted to ISO at the boundary. An
  undated row is kept (losing a transaction is the worse failure) but warned
  about, since it cannot be placed in a window.
- Read by: `transactions list`, and (filtered) `interest list`. Consumed by
  tax-cli's spending capture (the household burn rate).
- Source: `jjoelj/actual-bank-sync` `banks/sofi.js` + `content/sofi.js`.

### 3.5 Customer profile — `GET /banking-service/api/public/v2/customer` — UNVERIFIED-LIVE, not wired

`{ firstName, lastName, sofiId, email, phoneNumber, twoFactor{ twoFactorType:
"SMSV1", … }, addresses[], … }`. Documented and modelled in a fixture, but not
yet surfaced by a command — reachable via `sfi api GET
/banking-service/api/public/v2/customer` for exploration. Source:
`lijunle/bank-statement-downloader` `analyze/sofi.md`.

### 3.6 Not implemented

- **Tax forms (1099-INT).** No community project maps a tax-document endpoint.
  `documents --type tax` is accepted but currently matches nothing; wiring the
  real endpoint is deferred to the first live session (§7). Until then, the
  interest figures come from the accounts endpoint (§3.2) and the transaction
  heuristic (§3.4).
- **SoFi Invest.** REST per SoFi's blog, but the endpoints are not
  community-documented (the Invest projects are Selenium DOM automation). Out
  of scope for a Bank CLI.
- **Credit card.** SoFi's credit card has its own REST endpoints
  (`/credit-card-aggregator/api/public/v1/overview`, a CSV export at
  `/credit-card-servicing/api/public/v1/transactions/export`), but this CLI is
  for the household's checking + savings and does not read them.

## 4. Errors, limits, and lockout

- **Cloudflare** fronts the site; a non-browser User-Agent is blocked, so the
  client sends a realistic browser UA (load-bearing, not cosmetic).
- **ThreatMetrix** binds a session to the originating device/browser, which is
  the deeper reason a headless login is impractical.
- **Rate limits/lockout thresholds are not community-documented.** Indirect
  signals: GraphQL `pageSize` caps at 500; SoFi support caps a manual
  transaction export at a 2-year range. `sfi` paces requests (300 ms) and does
  **one** login attempt with no retry loop — a loop against an SMS challenge is
  how an account gets locked.

### 4.1 How `sfi` maps them

| Situation | `CliError` | Exit |
|---|---|---|
| HTML where JSON expected (lapsed session, or a possible bot check / edge block on a 403, 429 or 5xx or a page titled as a challenge) | `Auth` | 3 |
| GraphQL `errors` with an auth/session message | `Auth` | 3 |
| `401`; a `403` without an HTML page, which names both causes | `Auth` | 3 |
| `404` | `NotFound` | 4 |
| `429` / other 5xx without an HTML page / GraphQL error | `Upstream` | 5 |
| Download not a `%PDF` | `Upstream` (verify) | 5 |

## 5. Terms of service — an honest reading

SoFi's terms discourage automated/programmatic access. This tool is a personal,
read-only convenience for the account owner's own data, does one login attempt,
and never places a transfer, payment, or settings change. Using it still
carries provider-side risk (rate limiting, MFA loops, account restriction)
that a supported API would not. Treat `auth login` as owner-present-only.

## 6. The first live session — status after 2026-08-24

The first live session ran. **Done:** login (§2.2), accounts (§3.2),
net-worth, `interest ytd` (via `provider_estimate`), and `documents list`
(§3.3) — all LIVE-VERIFIED 2026-08-24. **Remaining:**

1. **Transactions (§3.4) — confirm the date fix.** The read answers live
   (since 2026-08-31); the `MMDDYYYY` date parser (2026-10-01) awaits one
   owner-present read: `sfi transactions list --since <date> --json` should
   date every row and print no undated warning. `sfi interest list` and the
   `interest ytd` YTD-vs-projection question (§3.2) both ride on this feed.
2. **`documents download` (§3.3) — unprobed.** Run `sfi documents download <id>
   -o /tmp/s.pdf` and confirm a real `%PDF`.
3. **Which domain's cookies the app requires (§2.5).** While signed in, note in
   DevTools → Application → Cookies which cookies live on `login.sofi.com` vs
   `www.sofi.com`.

Capture each raw response **outside the repo** (`sfi api GET <path> >
/tmp/raw.json`), then hand-copy the structure into the fixtures with values
scrubbed, and move each endpoint's label to **LIVE-VERIFIED <date>** as it is
confirmed.

## 7. Follow-ups

- **Login: DONE — browser harvest LIVE-VERIFIED (§2.2, 2026-08-24).** The
  modeled password-POST endpoint was confirmed dead (§2.6) and replaced by `sfi
  auth login --browser`. The `--code` password mechanics are retained but
  dead-live.
- **Reads: mostly DONE.** accounts, net-worth, `interest ytd`, and `documents
  list` are LIVE-VERIFIED 2026-08-24 (§3.2, §3.3); transactions answer live
  (§3.4, 2026-08-31). **Remaining:** the transactions date fix needs one
  owner-present read to confirm (§3.4), and `documents download` is unprobed.
- **`interest ytd`: YTD-so-far vs full-year projection (open).** LIVE the
  provider's `estimatedInterestThisYear` is reported as-is (`source:
  provider_estimate`); which of the two it means is unresolved (§3.2). The
  transactions feed will settle it by summing actual interest payments, now
  that its rows carry dates (§3.4). Flagged here and in §3.2; the consumer
  (tax-cli) should treat the YTD figure as an estimate, not a 1099-INT number,
  until then.
- **Which domain's cookies the app requires (§2.5).** Today the client sends
  the four session cookies of §2.4, wherever in the `sofi.com` jar they were
  set; confirm whether the app API needs only the `www.sofi.com` set.
- **Tax forms.** Find the tax-document endpoint during the live session and
  wire `documents --type tax` to it; today it returns nothing.
- **`interest list` heuristic.** The interest `displayType` is a guess
  (`is_interest` matches "interest" in the category or description). Confirm
  the real category word live and tighten it.
- **Vault accounts.** The GraphQL query includes a `VaultAccount` fragment;
  confirm whether vaults should count toward the emergency-fund `net-worth`
  figure or be reported separately.

## Sources

Direct private-API projects (primary):

- `lijunle/bank-statement-downloader` — `analyze/sofi.md`, `bank/sofi.mjs`
  (2025-11 → 2025-12). The cookie model and the REST endpoints (§2.4, §3.1,
  §3.3, §3.4).
- `jjoelj/actual-bank-sync` — `packages/extension/src/content/sofi.js`,
  `packages/extension/src/banks/sofi.js` (2026-04 → 2026-06). The GraphQL
  `Transactions` operation (§3.2).
- `jjoelj/sure-bank-sync` — sibling/mirror of the above.

Login / anti-bot context (Selenium DOM automation, no API):

- `penguinGuy47/stock_autobuy` — the Cloudflare-UA note and the Auth0 login URL.
- `EClinick/SOFI-AUTO` — the Auth0 `#username`/`#password`/`#code` form fields.

Corroborating:

- SoFi engineering blog (2025-10) — "REST … in Invest … a GraphQL-based BFF in
  Bank" confirms the two-style split.
- apitracker.io / an open feature request — confirm no public API.
- openbankingtracker — SoFi via Plaid/MX/Tink/TrueLayer aggregators (the
  indirect alternative; not used here).
