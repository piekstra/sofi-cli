//! `sfi transactions list` — account transactions in a date range, the
//! spending/burn-rate raw material for tax-cli's ingestion.
//!
//! # Where these come from
//!
//! SoFi's Bank has **no REST transactions collection**; the web app reads them
//! from a GraphQL BFF (`POST /bff/graphql`, operation `Transactions`). The
//! response nests each row under `data.me.accounts[].transactions.list[]` as
//! `{ cursor, transaction: { id, amount{unformatted}, createdDate{mmddyyyy},
//! description, displayType, expandedFields[]{title,value}, state } }`, paginated by `afterCursor`. Only
//! `state == "POSTED"` rows are settled — pending rows are excluded so a
//! burn-rate figure isn't inflated by holds that may never clear. See
//! docs/api.md §3.4.

use pk_cli_core::{CliError, Paged, RangeArgs};
use serde::Serialize;
use serde_json::{json, Value};

use crate::client::Session;
use crate::commands::accounts;
use crate::commands::{date_within, iso_from_mmddyyyy, money_of, str_at, Ctx};

/// Page size the web app requests. The BFF caps it here.
const PAGE_SIZE: u32 = 500;
/// A hard ceiling on pages, so an unbounded cursor chain can't turn one read
/// into thousands of requests against a rate-limited BFF.
const MAX_PAGES: u32 = 50;
/// Default lookback when no `--since` is given: a bank's own default window.
const DEFAULT_DAYS: u32 = 90;

/// The `Transactions` operation. Kept verbatim from the community capture so a
/// field the BFF requires is never dropped in a rewrite (docs/api.md §3.4).
const QUERY: &str = "query Transactions($accountIDs:[ID!],$pageSize:Int!,$afterCursor:String,$filter:MoneyTransactionFilter){ \
me{ accounts(filter:{accountIDs:$accountIDs}){ \
... on CheckingAccount{ id transactions(pageSize:$pageSize,afterCursor:$afterCursor,filter:$filter){ ...txList } } \
... on SavingsAccount{ id transactions(pageSize:$pageSize,afterCursor:$afterCursor,filter:$filter){ ...txList } } \
... on VaultAccount{ id transactions(pageSize:$pageSize,afterCursor:$afterCursor,filter:$filter){ ...txList } } \
} } } \
fragment txList on PaginatedMoneyTransactionList{ list{ cursor transaction{ id amount{unformatted} createdDate{mmddyyyy} description displayType expandedFields{title value} state } } }";

/// One transaction (`transaction/v1`).
#[derive(Debug, Serialize)]
pub struct Transaction {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<pk_cli_core::Money>,
    /// The provider's own category word (`DEPOSIT`, `WITHDRAWAL`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The counterparty the app shows as "Merchant" (the `expandedFields`
    /// entry titled `Merchant`), when the row carries one — a cleaner key
    /// for categorizing spending than the raw description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

impl Transaction {
    /// Map a `{ cursor, transaction: {…} }` list entry, tagging it with its
    /// account id.
    pub fn from_entry(entry: &Value, account_id: &str) -> Option<Self> {
        let tx = entry.get("transaction")?;
        let id = str_at(tx, "id")?;
        Some(Transaction {
            id,
            date: tx
                .pointer("/createdDate/mmddyyyy")
                .and_then(Value::as_str)
                .and_then(iso_from_mmddyyyy),
            description: str_at(tx, "description"),
            amount: tx.pointer("/amount/unformatted").and_then(money_of),
            kind: str_at(tx, "displayType"),
            merchant: merchant_of(tx),
            state: str_at(tx, "state"),
            account_id: Some(account_id.to_string()),
        })
    }

    fn date_str(&self) -> Option<&str> {
        self.date.as_deref()
    }
}

/// The `expandedFields` entry titled `Merchant`, if any.
fn merchant_of(tx: &Value) -> Option<String> {
    tx.get("expandedFields")?
        .as_array()?
        .iter()
        .find(|f| f.get("title").and_then(Value::as_str) == Some("Merchant"))
        .and_then(|f| str_at(f, "value"))
}

/// How many rows carry no readable date. An undated row is kept (losing a
/// transaction is worse) but cannot be placed in a window, so each command
/// warns over the rows it reports.
pub fn undated_count<'a>(dates: impl Iterator<Item = Option<&'a str>>) -> usize {
    dates.filter(Option::is_none).count()
}

/// The undated-row warning, on stderr unless `--quiet`.
pub fn warn_undated(ctx: &Ctx, undated: usize) {
    if undated > 0 && !ctx.common.quiet {
        eprintln!(
            "warning: {undated} row(s) carry no readable createdDate — kept, but outside \
             any --since/--until check (docs/api.md §3.4)"
        );
    }
}

/// Whether a transaction is settled. Pending holds may never clear, so they
/// are excluded from a settled-ledger read.
pub fn is_posted(entry: &Value) -> bool {
    entry
        .pointer("/transaction/state")
        .and_then(Value::as_str)
        .map(|s| s.eq_ignore_ascii_case("POSTED"))
        .unwrap_or(false)
}

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    let mut items = collect(ctx, range)?;
    warn_undated(ctx, undated_count(items.iter().map(|t| t.date.as_deref())));
    // `collect` already sorts newest-first; `--limit N` then means "the N most
    // recent".
    if let Some(n) = range.limit {
        items.truncate(n as usize);
    }
    Paged::new("transaction", items).emit(ctx.common.json);
    Ok(())
}

/// Fetch every settled transaction in the date range, newest first. The
/// `--limit` slice is applied by the caller so a consumer (e.g. `interest`,
/// which filters first) can take its own N. Shared by `transactions list` and
/// the interest reconstruction.
pub fn collect(ctx: &Ctx, range: &RangeArgs) -> Result<Vec<Transaction>, CliError> {
    let session = ctx.session()?;

    // Which accounts to pull. An explicit -a/--account narrows to one; the
    // config default is honored here (a persisted default narrowing a ledger
    // is harmless, unlike net-worth).
    let account_ids: Vec<String> = match &ctx.account {
        Some(a) => vec![a.clone()],
        None => accounts::fetch(ctx)?
            .iter()
            .filter(|r| accounts::is_active(r))
            .filter_map(|r| str_at(r, "id"))
            .collect(),
    };
    if account_ids.is_empty() {
        return Err(CliError::NotFound(
            "no active account to read transactions from — run `sfi accounts list`".into(),
        ));
    }

    let days = lookback_days(range.since.as_deref());
    let mut items: Vec<Transaction> = Vec::new();
    for account_id in &account_ids {
        let (entries, _capped) = fetch_entries(ctx, &session, account_id, days)?;
        for entry in &entries {
            if !is_posted(entry) {
                continue;
            }
            if let Some(tx) = Transaction::from_entry(entry, account_id) {
                if in_range(&tx, range) {
                    items.push(tx);
                }
            }
        }
    }

    // Newest first.
    items.sort_by(|a, b| b.date_str().cmp(&a.date_str()));
    Ok(items)
}

/// One account's list entries, every state, walked back `days` days page by
/// page; and whether [`MAX_PAGES`] stopped the walk before the history ran
/// out. Shared by [`collect`] and the MCP tools.
pub fn fetch_entries(
    ctx: &Ctx,
    session: &Session,
    account_id: &str,
    days: u32,
) -> Result<(Vec<Value>, bool), CliError> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let variables = json!({
            "accountIDs": [account_id],
            "pageSize": PAGE_SIZE,
            "afterCursor": cursor,
            "filter": { "days": days, "dateRange": null, "searchText": null,
                        "amountFilter": null, "transactionTypes": null },
        });
        let data = ctx
            .sofi
            .graphql(session, "Transactions", QUERY, variables)?;
        let entries = transaction_entries(&data, account_id);
        let page_len = entries.len();
        cursor = last_cursor(&entries);
        all.extend(entries);
        if page_exhausted(page_len, &cursor) {
            return Ok((all, false));
        }
    }
    Ok((all, true))
}

/// Whether a fetched page ends an account's walk: ONLY an empty page or a
/// missing cursor. The server CAPS pages at 100 regardless of the requested
/// pageSize (live 2026-08-31: pageSize 500 answered exactly 100 rows WITH a
/// cursor), so a short-but-cursored page is the cap, not the end of history
/// — breaking on `page_len < PAGE_SIZE` silently truncated a busy account's
/// year to its newest 100 rows and understated `interest list` (a 1099-INT
/// feed) by every payment older than the first page.
fn page_exhausted(page_len: usize, cursor: &Option<String>) -> bool {
    page_len == 0 || cursor.is_none()
}

/// The lookback window the BFF filter takes. `--since` becomes a day count
/// (the server has no `dateRange` the community code exercises); `--until` is
/// applied client-side. No `--since` means the default window.
pub fn lookback_days(since: Option<&str>) -> u32 {
    match since.and_then(days_since_iso) {
        // A little slack so the boundary day is never trimmed server-side; the
        // exact bound is enforced client-side by `in_range`.
        Some(d) => d.saturating_add(2),
        None => DEFAULT_DAYS,
    }
}

/// Whole days from an ISO date to today (0 if the date is in the future).
fn days_since_iso(since: &str) -> Option<u32> {
    let since = pk_cli_core::dates::parse_iso(since).ok()?;
    let today = pk_cli_core::dates::today();
    let d = days_from_civil(today) - days_from_civil(since);
    Some(d.max(0) as u32)
}

/// Days since a fixed epoch for a `(y, m, d)` civil date — Howard Hinnant's
/// algorithm, used only to difference two dates (never to format one; that is
/// `pk_cli_core::dates`' job).
fn days_from_civil((y, m, d): (i64, u32, u32)) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn in_range(tx: &Transaction, range: &RangeArgs) -> bool {
    match tx.date_str() {
        Some(d) => date_within(d, range.since.as_deref(), range.until.as_deref()),
        // An undated row is kept rather than silently dropped — losing a
        // transaction is the worse failure for a burn-rate figure.
        None => true,
    }
}

/// The list entries out of a `Transactions` response's data object.
pub fn transaction_entries(data: &Value, _account_id: &str) -> Vec<Value> {
    data.pointer("/me/accounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|acct| acct.pointer("/transactions/list").and_then(Value::as_array))
        .flatten()
        .cloned()
        .collect()
}

/// The cursor of the last entry, for the next page request.
fn last_cursor(entries: &[Value]) -> Option<String> {
    entries
        .last()
        .and_then(|e| e.get("cursor"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    /// The server-cap regression: a 100-row page WITH a cursor is the
    /// server's page cap, not the end of history — the old
    /// `page_len < PAGE_SIZE` break truncated busy accounts to one page.
    #[test]
    fn a_capped_but_cursored_page_does_not_end_the_walk() {
        let cursor = Some("abc".to_string());
        assert!(
            !page_exhausted(100, &cursor),
            "a short-but-cursored page must continue (PAGE_SIZE is {PAGE_SIZE})"
        );
        assert!(page_exhausted(0, &cursor), "an empty page ends the walk");
        assert!(page_exhausted(100, &None), "a missing cursor ends the walk");
    }

    use super::*;

    fn entry(id: &str, date: &str, amount: &str, state: &str, cursor: &str) -> Value {
        json!({
            "cursor": cursor,
            "transaction": {
                "id": id,
                "amount": {"unformatted": amount},
                "createdDate": {"mmddyyyy": date},
                "description": "Sample Merchant",
                "displayType": "WITHDRAWAL",
                "expandedFields": [{"title": "Merchant", "value": "Sample Merchant"}],
                "state": state
            }
        })
    }

    #[test]
    fn maps_the_entry_fields_and_converts_the_date() {
        let t =
            Transaction::from_entry(&entry("t1", "07/04/2026", "-42.50", "POSTED", "c1"), "1111")
                .unwrap();
        assert_eq!(t.date.as_deref(), Some("2026-07-04"));
        assert_eq!(t.account_id.as_deref(), Some("1111"));
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["amount"]["amount"], "-42.50");
        assert_eq!(v["kind"], "WITHDRAWAL");
        assert_eq!(v["description"], "Sample Merchant");
        assert_eq!(v["merchant"], "Sample Merchant");
    }

    #[test]
    fn undated_rows_are_counted() {
        let dates = [Some("2026-07-04"), None, None];
        assert_eq!(undated_count(dates.into_iter()), 2);
        assert_eq!(undated_count(std::iter::empty()), 0);
    }

    /// The live wire format is unseparated `MMDDYYYY`; a row in it must
    /// date (the slashed-only parser left every live row undated).
    #[test]
    fn the_unseparated_wire_date_is_read() {
        let t = Transaction::from_entry(&entry("t1", "07042026", "-1.00", "POSTED", "c1"), "1111")
            .unwrap();
        assert_eq!(t.date.as_deref(), Some("2026-07-04"));
    }

    #[test]
    fn a_row_without_a_merchant_field_has_none() {
        let e = json!({"cursor": "c", "transaction": {"id": "x", "expandedFields": [
            {"title": "Category", "value": "Other"}]}});
        assert!(Transaction::from_entry(&e, "1").unwrap().merchant.is_none());
        let bare = json!({"cursor": "c", "transaction": {"id": "x"}});
        assert!(Transaction::from_entry(&bare, "1")
            .unwrap()
            .merchant
            .is_none());
    }

    #[test]
    fn only_posted_rows_are_settled() {
        assert!(is_posted(&entry(
            "t1",
            "07/04/2026",
            "-1.00",
            "POSTED",
            "c1"
        )));
        assert!(!is_posted(&entry(
            "t2",
            "07/04/2026",
            "-1.00",
            "PENDING",
            "c2"
        )));
        assert!(!is_posted(&json!({"transaction": {"id": "x"}})));
    }

    #[test]
    fn entries_are_pulled_from_the_graphql_shape() {
        let data = json!({
            "me": { "accounts": [
                { "id": "1111", "transactions": { "list": [
                    entry("t1", "07/04/2026", "-1.00", "POSTED", "c1"),
                    entry("t2", "07/03/2026", "-2.00", "POSTED", "c2")
                ] } }
            ] }
        });
        let entries = transaction_entries(&data, "1111");
        assert_eq!(entries.len(), 2);
        assert_eq!(last_cursor(&entries).as_deref(), Some("c2"));
        assert!(last_cursor(&[]).is_none());
    }

    #[test]
    fn range_filtering_is_inclusive_and_keeps_undated_rows() {
        let t =
            Transaction::from_entry(&entry("t1", "07/04/2026", "-1.00", "POSTED", "c1"), "1111")
                .unwrap();
        let range = |s: &str, u: &str| RangeArgs {
            limit: None,
            since: Some(s.into()),
            until: Some(u.into()),
        };
        assert!(in_range(&t, &range("2026-07-04", "2026-07-04")));
        assert!(!in_range(&t, &range("2026-07-05", "2026-12-31")));
        // Undated survives.
        let undated = Transaction {
            id: "x".into(),
            date: None,
            description: None,
            amount: None,
            kind: None,
            merchant: None,
            state: None,
            account_id: None,
        };
        assert!(in_range(&undated, &range("2026-01-01", "2026-12-31")));
    }

    #[test]
    fn lookback_widens_the_window_by_a_slack_day_or_two() {
        // No since → the default window.
        assert_eq!(lookback_days(None), DEFAULT_DAYS);
        // A since in the future is clamped to a tiny window, never negative.
        let far_future = "2999-01-01";
        assert!(lookback_days(Some(far_future)) <= 2);
    }

    #[test]
    fn days_from_civil_differences_dates_correctly() {
        // One week apart.
        assert_eq!(
            days_from_civil((2026, 7, 11)) - days_from_civil((2026, 7, 4)),
            7
        );
        // Across a year boundary.
        assert_eq!(
            days_from_civil((2027, 1, 1)) - days_from_civil((2026, 12, 31)),
            1
        );
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new(
            "transaction",
            vec![Transaction::from_entry(
                &entry("t1", "07/04/2026", "-1.00", "POSTED", "c1"),
                "1111",
            )
            .unwrap()],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "transaction-list/v1");
        assert_eq!(v["items"][0]["id"], "t1");
    }
}
