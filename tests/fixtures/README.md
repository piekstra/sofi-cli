# Fixtures

**These are NOT captures.** Every file here is **synthetic**: every value is a
dummy per the policy below, and no raw capture has ever entered the repo.
Their *structure* — key names, nesting, types, null-vs-absent — is modelled on
public community documentation (the two browser-extension projects cited in
`docs/api.md`), hand-written on 2026-08-21 with every value replaced. **None of
it has been confirmed against the live SoFi service by this project** — the
endpoints are UNVERIFIED-LIVE, and these fixtures are only as accurate as the
community sources they model.

That matters twice over: this repo is written as if it were public, and a real
capture from a SoFi account carries account numbers, balances, transactions,
and — for a statement link — a possible pre-signed credential.

`tests/fixture_shapes.rs` asserts that the fields the CLI's views read still
exist, so a modelled-shape mistake or an upstream rename fails the build
instead of silently emptying a column. It also enforces the synthetic-value
policy below.

## Provenance

Structure is modelled on these community sources (see `docs/api.md` for the
full citations). Where sources disagreed, the newest was preferred.

| File | Modelled on |
| --- | --- |
| `accounts.json` | `lijunle/bank-statement-downloader` `analyze/sofi.md` + `jjoelj/actual-bank-sync` — `GET /money/api/public/v2/accounts` (docs/api.md §3.2) |
| `transactions.json` | `jjoelj/actual-bank-sync` `banks/sofi.js` — the `Transactions` GraphQL operation on `/bff/graphql` (docs/api.md §3.4). Includes one `PENDING` row to pin that pending is excluded |
| `interest_transactions.json` | same GraphQL shape as `transactions.json`, with `displayType: "INTEREST"` rows — the heuristic `interest list` matches (docs/api.md §3.4) |
| `statements.json` | `lijunle/bank-statement-downloader` `bank/sofi.mjs` — `GET /banking-service/api/public/v2/statements` (docs/api.md §3.3) |
| `customer.json` | `lijunle/bank-statement-downloader` `analyze/sofi.md` — `GET /banking-service/api/public/v2/customer` (documented; not wired into a command yet) |
| `login_mfa_required.json` | modelled MFA-challenge body (docs/api.md §2) — **UNVERIFIED**, the login flow is the least certain part of the model |
| `login_error.json` | modelled credential-rejection body (docs/api.md §2) — **UNVERIFIED** |
| `graphql_error.json` | GraphQL BFF error envelope — a 200 carrying an `errors` array, the auth-expiry shape (docs/api.md §3.4) |

## Value policy

No fixture may carry anything that identifies a real account, person, balance,
or transaction. Types and formats are preserved exactly, since the parsers
depend on them; values are obvious dummies:

| Value | Dummy used |
| --- | --- |
| Account ids | `1111`, `2222` |
| Account numbers | `****1234`, `****5678` (already masked) |
| UUIDs (ids, tokens, party ids) | `00000000-0000-4000-8000-…` |
| Nicknames / names | `Sample …`, `Test …` |
| Money / balances / APY | round dummies (`2500.00`, `4.00%`) |
| Usernames / emails | `user@example.com` |
| Phone numbers | `+10000000000`, `***0000` |
| Descriptions / merchants | `Sample …` |

Dates, booleans, and enum-ish strings (`CHECKING`, `POSTED`, `COMBINED`,
`MFA_REQUIRED`, `SMSV1`) are kept realistic — they carry no personal
information and the parsing logic depends on their exact form.

The enforcement test is written **positively** ("identity-bearing fields must
hold a known dummy shape") rather than as a denylist of real values, because a
denylist would itself publish the values it exists to keep out of the repo.

## Refreshing

If a shape needs checking against reality, capture with
`sfi api GET <path> > /tmp/raw.json` — **outside the repo** — and hand-copy the
*structure* back, applying the table above. `raw-*.json`, `capture-*.json`, and
`*.raw.json` are gitignored as a backstop, but the rule is simply: **never
commit a capture.** A statement link may be a working credential, and the
account data is real.
