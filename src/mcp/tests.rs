//! The `sfi mcp` tools, offline: every tool runs in process against the
//! synthetic fixtures through the `Source` seam, mapped by the commands' own
//! mappers, and cli-common's conformance helper checks the definitions and
//! every result's shape and size.

use std::collections::BTreeMap;
use std::sync::Mutex;

use pk_cli_core::CliError;
use pk_cli_mcp::conformance::{assert_conforms, assert_fits, call, definition_size};
use pk_cli_mcp::CallToolResult;
use serde_json::{json, Value};

use super::*;

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture parses")
}

const CHECKING: &str = "1111";
const SAVINGS: &str = "2222";

struct Fixtures {
    accounts: Vec<Value>,
    /// Each account's transaction list entries: the checking fixture's for
    /// 1111, the interest fixture's for 2222.
    feeds: BTreeMap<String, Vec<Value>>,
    statements: Vec<Value>,
    /// When set, every transactions walk reports the page ceiling hit.
    capped: bool,
    /// Every source call, as `method:args`.
    calls: Mutex<Vec<String>>,
    /// When set, every call fails with this.
    fail: Mutex<Option<CliError>>,
}

impl Fixtures {
    fn new() -> Self {
        let accounts = fixture(include_str!("../../tests/fixtures/accounts.json"));
        let checking = fixture(include_str!("../../tests/fixtures/transactions.json"));
        let savings = fixture(include_str!(
            "../../tests/fixtures/interest_transactions.json"
        ));
        let statements = fixture(include_str!("../../tests/fixtures/statements.json"));
        let mut feeds = BTreeMap::new();
        feeds.insert(
            CHECKING.to_string(),
            transactions::transaction_entries(&checking["data"], CHECKING),
        );
        feeds.insert(
            SAVINGS.to_string(),
            transactions::transaction_entries(&savings["data"], SAVINGS),
        );
        Self {
            accounts: accounts::account_rows(&accounts),
            feeds,
            statements: statements.as_array().unwrap().clone(),
            capped: false,
            calls: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
        }
    }

    fn record(&self, call: String) -> Result<(), CliError> {
        self.calls.lock().unwrap().push(call);
        match self.fail.lock().unwrap().as_ref() {
            None => Ok(()),
            Some(e) => Err(e.clone()),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Source for Fixtures {
    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        self.record("accounts".into())?;
        Ok(self.accounts.clone())
    }

    async fn transactions(
        &self,
        account_id: &str,
        since: &str,
    ) -> Result<(Vec<Value>, bool), CliError> {
        self.record(format!("transactions:{account_id}:{since}"))?;
        let entries = self.feeds.get(account_id).cloned().unwrap_or_default();
        Ok((entries, self.capped))
    }

    async fn statements(&self) -> Result<Vec<Value>, CliError> {
        self.record("statements".into())?;
        Ok(self.statements.clone())
    }
}

fn tools() -> SofiTools<Fixtures> {
    SofiTools::new(Fixtures::new())
}

fn with(f: impl FnOnce(&mut Fixtures)) -> SofiTools<Fixtures> {
    let mut fixtures = Fixtures::new();
    f(&mut fixtures);
    SofiTools::new(fixtures)
}

/// A posted list entry; `date` is SoFi's MMDDYYYY, absent when `None`.
fn entry(id: &str, date: Option<&str>, amount: &str, kind: &str, description: &str) -> Value {
    let mut tx = json!({
        "id": id,
        "amount": {"unformatted": amount},
        "description": description,
        "displayType": kind,
        "expandedFields": [],
        "state": "POSTED"
    });
    if let Some(d) = date {
        tx["createdDate"] = json!({"mmddyyyy": d});
    }
    json!({"cursor": format!("c-{id}"), "transaction": tx})
}

fn err(r: &CallToolResult) -> &str {
    assert!(r.is_error(), "expected an error, got {}", r.text());
    assert!(r.structured().is_none());
    r.text()
}

fn field(items: &Value, key: &str) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i[key].as_str().unwrap_or("-").to_string())
        .collect()
}

const TOOLS: [&str; 4] = [
    BALANCES_TOOL,
    TRANSACTIONS_TOOL,
    INTEREST_TOOL,
    DOCUMENTS_TOOL,
];

// ---- the definitions --------------------------------------------------------

#[test]
fn the_tools_conform_to_the_mcp_profile() {
    assert_conforms(&tools());
}

#[test]
fn the_definitions_stay_small() {
    let t = tools();
    let mut total = 0;
    for name in TOOLS {
        let size = definition_size(&t, name);
        eprintln!("{name}: {size} characters");
        assert!(size < 2_500, "{name} takes {size} characters");
        total += size;
    }
    eprintln!("total: {total} characters");
    assert!(total <= 8_000, "the definitions take {total} characters");
}

#[test]
fn listing_and_describing_the_tools_reads_nothing() {
    let t = tools();
    let _ = t.tools();
    let _ = t.server();
    assert!(t.source().calls().is_empty());
}

// ---- sofi_balances ----------------------------------------------------------

#[test]
fn balances_are_named_and_totalled() {
    let t = tools();
    let r = call(&t, BALANCES_TOOL, json!({}));
    let out = assert_fits(&t, BALANCES_TOOL, &r);
    assert_eq!(out["total"], "12750.50");
    assert!(out.get("unvalued").is_none());
    assert_eq!(
        field(&out["items"], "name"),
        ["Sample Checking", "Sample Savings"]
    );
    assert_eq!(field(&out["items"], "type"), ["checking", "savings"]);
    assert_eq!(field(&out["items"], "available"), ["2500.00", "10250.50"]);
    assert_eq!(field(&out["items"], "apy"), ["0.50%", "3.10%"]);
    let first = &out["items"][0];
    for key in ["id", "ledger", "number"] {
        assert!(first.get(key).is_none(), "concise: {first}");
    }
    assert_eq!(t.source().calls(), ["accounts"]);
}

#[test]
fn detailed_balances_add_the_posted_balance_mask_and_id() {
    let t = tools();
    let r = call(&t, BALANCES_TOOL, json!({"response_format": "detailed"}));
    let out = assert_fits(&t, BALANCES_TOOL, &r);
    assert_eq!(field(&out["items"], "ledger"), ["2480.00", "10250.50"]);
    assert_eq!(field(&out["items"], "number"), ["****1234", "****5678"]);
    assert_eq!(field(&out["items"], "id"), [CHECKING, SAVINGS]);
}

#[test]
fn an_account_is_picked_by_name_mask_or_id_and_narrows_the_total() {
    let t = tools();
    for wanted in ["sample savings", "****5678", SAVINGS] {
        let r = call(&t, BALANCES_TOOL, json!({"account": wanted}));
        let out = assert_fits(&t, BALANCES_TOOL, &r);
        assert_eq!(field(&out["items"], "name"), ["Sample Savings"], "{wanted}");
        assert_eq!(out["total"], "10250.50", "{wanted}");
    }
}

#[test]
fn an_unknown_account_lists_the_names_that_exist() {
    let t = tools();
    let text = err(&call(&t, BALANCES_TOOL, json!({"account": "Rainy Day"}))).to_string();
    assert!(text.starts_with("not_found:"), "{text}");
    assert!(text.contains("Sample Checking, Sample Savings"), "{text}");
}

#[test]
fn closed_accounts_are_left_out_unnamed_ones_get_a_label_and_unvalued_ones_count_apart() {
    let t = with(|f| {
        f.accounts.extend([
            json!({
                "id": "3333", "type": "SAVING", "number": "****0003", "status": "CLOSED",
                "nickname": "Old Vault", "balance": {"available": "99.00", "ledger": "99.00"}
            }),
            json!({
                "id": "4444", "type": "SAVING", "number": "****0004", "status": "ACTIVE",
                "balance": {"available": "1.25", "ledger": "1.25"}
            }),
            json!({"id": "5555", "type": "CHECKING", "number": "****0005", "status": "ACTIVE"}),
        ]);
    });
    let r = call(&t, BALANCES_TOOL, json!({}));
    let out = assert_fits(&t, BALANCES_TOOL, &r);
    assert_eq!(
        field(&out["items"], "name"),
        [
            "Sample Checking",
            "Sample Savings",
            "savings ****0004",
            "checking ****0005"
        ]
    );
    assert_eq!(out["total"], "12751.75");
    assert_eq!(out["unvalued"], 1);
    assert!(out["items"][3].get("available").is_none());
}

#[test]
fn an_unreadable_balance_is_counted_apart_never_as_zero() {
    let t = with(|f| f.accounts[0]["balance"]["available"] = Value::Null);
    let r = call(&t, BALANCES_TOOL, json!({}));
    let out = assert_fits(&t, BALANCES_TOOL, &r);
    assert_eq!(out["total"], "10250.50");
    assert_eq!(out["unvalued"], 1);
    assert_eq!(out["items"][0]["name"], "Sample Checking");
    assert!(out["items"][0].get("available").is_none());
}

#[test]
fn balances_page_with_a_cursor_bound_to_the_filters() {
    let t = tools();
    let first = call(&t, BALANCES_TOOL, json!({"limit": 1}));
    let out = assert_fits(&t, BALANCES_TOOL, &first);
    assert_eq!(field(&out["items"], "name"), ["Sample Checking"]);
    assert_eq!(out["total"], "12750.50", "the total is not the page's");
    let cursor = out["next_cursor"].as_str().unwrap().to_string();

    let second = call(&t, BALANCES_TOOL, json!({"limit": 1, "cursor": cursor}));
    let out = assert_fits(&t, BALANCES_TOOL, &second);
    assert_eq!(field(&out["items"], "name"), ["Sample Savings"]);
    assert!(out.get("next_cursor").is_none());

    let other = call(
        &t,
        BALANCES_TOOL,
        json!({"limit": 1, "cursor": cursor, "account": "Sample Savings"}),
    );
    assert!(err(&other).starts_with("usage:"));
}

// ---- sofi_transactions ------------------------------------------------------

#[test]
fn transactions_are_settled_and_newest_first_across_accounts() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["since"], "2026-01-01");
    assert_eq!(out["complete"], true);
    // The pending -9.99 hold is not a settled transaction.
    assert_eq!(
        field(&out["items"], "date"),
        ["2026-07-31", "2026-07-28", "2026-07-15", "2026-06-30"]
    );
    assert_eq!(
        field(&out["items"], "amount"),
        ["34.16", "-42.50", "1500.00", "31.02"]
    );
    assert_eq!(
        field(&out["items"], "type"),
        ["INTEREST", "WITHDRAWAL", "DEPOSIT", "INTEREST"]
    );
    assert_eq!(
        field(&out["items"], "account"),
        [
            "Sample Savings",
            "Sample Checking",
            "Sample Checking",
            "Sample Savings"
        ]
    );
    assert_eq!(out["items"][1]["merchant"], "Sample Grocery Store");
    assert!(out["items"][0].get("id").is_none(), "concise");
    assert_eq!(
        t.source().calls(),
        [
            "accounts",
            "transactions:1111:2026-01-01",
            "transactions:2222:2026-01-01"
        ]
    );
}

#[test]
fn transactions_narrow_by_window_account_and_type() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"since": "2026-07-01", "until": "2026-07-30", "type": "deposit"}),
    );
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(
        field(&out["items"], "description"),
        ["Sample Employer Payroll"]
    );

    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31", "account": "Sample Checking"}),
    );
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["returned"], 2);
    assert_eq!(
        t.source().calls(),
        ["accounts", "transactions:1111:2026-01-01"]
    );
}

#[test]
fn detailed_transactions_add_their_ids() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"since": "2026-07-28", "until": "2026-07-28", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(
        field(&out["items"], "id"),
        ["00000000-0000-4000-8000-000000000010"]
    );
}

/// As in `transactions list`: a row SoFi sent with no readable date is kept
/// in every window, after the dated ones, since losing it is the worse
/// failure.
#[test]
fn an_undated_transaction_is_kept_and_listed_last() {
    let t = with(|f| {
        f.feeds.get_mut(CHECKING).unwrap().push(entry(
            "00000000-0000-4000-8000-000000000013",
            None,
            "-5.00",
            "WITHDRAWAL",
            "Sample Coffee",
        ));
    });
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"since": "2026-07-01", "until": "2026-07-31"}),
    );
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["returned"], 4);
    assert_eq!(out["items"][3]["description"], "Sample Coffee");
    assert!(out["items"][3].get("date").is_none());
}

#[test]
fn a_walk_cut_short_marks_the_result_incomplete() {
    let t = with(|f| f.capped = true);
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["complete"], false);
}

#[test]
fn transactions_default_to_the_year_to_date() {
    let t = tools();
    let r = call(&t, TRANSACTIONS_TOOL, json!({"until": "2026-08-31"}));
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["since"], "2026-01-01");
    let today = dates::fmt_iso(dates::today());
    let r = call(&t, TRANSACTIONS_TOOL, json!({}));
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["until"], today);
    assert_eq!(out["since"], format!("{}-01-01", &today[..4]));
}

#[test]
fn bad_arguments_fail_before_any_read() {
    let t = tools();
    let current = dates::today().0;
    for (tool, args) in [
        (TRANSACTIONS_TOOL, json!({"since": "01/05/2026"})),
        (TRANSACTIONS_TOOL, json!({"until": "2026-13-01"})),
        (
            TRANSACTIONS_TOOL,
            json!({"since": "2026-09-01", "until": "2026-08-01"}),
        ),
        (
            DOCUMENTS_TOOL,
            json!({"since": "2026-09-01", "until": "2026-08-01"}),
        ),
        (DOCUMENTS_TOOL, json!({"until": "2026-1-x"})),
        (INTEREST_TOOL, json!({"year": 1999})),
        (INTEREST_TOOL, json!({"year": current + 1})),
    ] {
        let text = err(&call(&t, tool, args.clone())).to_string();
        assert!(text.starts_with("usage:"), "{tool} {args}: {text}");
    }
    assert!(t.source().calls().is_empty());
}

/// An unpadded date compares as a string, so it is padded first:
/// `"2026-8-5" < "2026-08-01"` as text, though 5 August is later.
#[test]
fn unpadded_dates_are_padded_before_any_comparison() {
    let (s, u) = window(Some("2026-8-5"), Some("2026-08-31")).unwrap();
    assert_eq!((s.as_str(), u.as_str()), ("2026-08-05", "2026-08-31"));
    let (s, _) = window(None, Some("2026-3-1")).unwrap();
    assert_eq!(s, "2026-01-01");
}

// ---- sofi_interest ----------------------------------------------------------

#[test]
fn this_year_s_interest_is_sofi_s_running_figure() {
    let t = tools();
    let r = call(&t, INTEREST_TOOL, json!({}));
    let out = assert_fits(&t, INTEREST_TOOL, &r);
    assert_eq!(out["year"], dates::today().0);
    assert_eq!(out["source"], "provider_estimate");
    assert_eq!(out["total"], "250.30");
    assert_eq!(out["lifetime"], "658.01");
    assert_eq!(field(&out["accounts"], "interest"), ["8.40", "241.90"]);
    assert_eq!(
        field(&out["accounts"], "name"),
        ["Sample Checking", "Sample Savings"]
    );
    assert_eq!(t.source().calls(), ["accounts"], "no transactions read");

    let r = call(&t, INTEREST_TOOL, json!({"account": "Sample Savings"}));
    let out = assert_fits(&t, INTEREST_TOOL, &r);
    assert_eq!(out["total"], "241.90");
    assert_eq!(out["lifetime"], "612.34");
}

#[test]
fn a_past_year_s_interest_sums_that_year_s_payments() {
    let t = with(|f| {
        f.feeds.insert(
            SAVINGS.to_string(),
            vec![
                entry(
                    "int-1",
                    Some("01312026"),
                    "21.00",
                    "INTEREST",
                    "Interest earned",
                ),
                entry(
                    "int-2",
                    Some("12312025"),
                    "20.00",
                    "INTEREST",
                    "Interest earned",
                ),
                entry(
                    "dep-1",
                    Some("12152025"),
                    "300.00",
                    "DEPOSIT",
                    "Transfer in",
                ),
                entry(
                    "int-3",
                    Some("11302025"),
                    "19.50",
                    "INTEREST",
                    "Interest earned",
                ),
                entry(
                    "int-4",
                    Some("12312024"),
                    "18.00",
                    "INTEREST",
                    "Interest earned",
                ),
                entry("int-5", None, "1.00", "INTEREST", "Interest earned"),
            ],
        );
    });
    let r = call(&t, INTEREST_TOOL, json!({"year": 2025}));
    let out = assert_fits(&t, INTEREST_TOOL, &r);
    assert_eq!(out["source"], "transactions");
    assert_eq!(out["total"], "39.50");
    assert!(out.get("lifetime").is_none());
    assert_eq!(
        out["undated"], 1,
        "an undated payment is in no year's total"
    );
    assert_eq!(out["complete"], true);
    assert_eq!(field(&out["accounts"], "interest"), ["0.00", "39.50"]);
    assert_eq!(
        t.source().calls(),
        [
            "accounts",
            "transactions:1111:2025-01-01",
            "transactions:2222:2025-01-01"
        ]
    );
}

// ---- sofi_documents ---------------------------------------------------------

#[test]
fn statements_are_listed_newest_first() {
    let t = tools();
    let r = call(&t, DOCUMENTS_TOOL, json!({}));
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(field(&out["items"], "date"), ["2026-07-31", "2026-06-30"]);
    assert_eq!(
        field(&out["items"], "name"),
        ["July 2026 Statement", "June 2026 Statement"]
    );
    assert!(out["items"][0].get("id").is_none(), "concise");
    assert_eq!(t.source().calls(), ["statements"]);
}

#[test]
fn statements_narrow_by_window_with_ids_on_request() {
    let t = tools();
    let r = call(
        &t,
        DOCUMENTS_TOOL,
        json!({"since": "2026-07-01", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(field(&out["items"], "date"), ["2026-07-31"]);
    assert_eq!(
        out["items"][0]["id"],
        "00000000-0000-4000-8000-000000000030"
    );
}

/// As in `documents list`: an undated statement is listed only when no
/// window is asked for.
#[test]
fn an_undated_statement_is_listed_only_without_a_window() {
    let t = with(|f| {
        f.statements.push(json!({
            "documentId": "00000000-0000-4000-8000-000000000032",
            "description": "Statement"
        }));
    });
    let r = call(&t, DOCUMENTS_TOOL, json!({}));
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(out["returned"], 3);
    let r = call(&t, DOCUMENTS_TOOL, json!({"until": "2026-12-31"}));
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(out["returned"], 2);
}

// ---- errors -----------------------------------------------------------------

#[test]
fn a_missing_session_asks_for_the_browser_login_in_a_terminal() {
    let t = tools();
    *t.source().fail.lock().unwrap() = Some(CliError::Auth(
        "no cached session — run `sfi auth login`".into(),
    ));
    for name in TOOLS {
        let text = err(&call(&t, name, json!({}))).to_string();
        assert!(text.starts_with("auth:"), "{name}: {text}");
        assert!(
            text.contains("Ask the user to run `sfi auth login --browser` in a terminal"),
            "{name}: {text}"
        );
        assert!(text.contains("never sign in"), "{name}: {text}");
    }
}

#[test]
fn a_provider_failure_is_upstream_not_the_arguments() {
    let t = tools();
    *t.source().fail.lock().unwrap() = Some(CliError::Upstream("HTTP 503".into()));
    let text = err(&call(&t, BALANCES_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(!text.contains("auth login"), "{text}");
}

#[test]
fn the_instructions_name_the_browser_login_and_read_only_access() {
    let text = pk_cli_mcp::instructions(&tools());
    assert!(text.contains("`sfi auth login --browser`"), "{text}");
    assert!(text.contains("read-only"), "{text}");
}
