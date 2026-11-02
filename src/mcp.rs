//! `sfi mcp`: SoFi balances, transactions, interest and statements as MCP
//! tools (cli-common DESIGN.md §1.9, the MCP profile), for Claude Code,
//! Claude Desktop and any MCP client.
//!
//! Four read-only tools over the same reads and mappers the commands use:
//! `sofi_balances` (each open account's balance and their total, the
//! `net-worth` reading), `sofi_transactions` (settled transactions over a
//! date range), `sofi_interest` (a year's interest by account, the `interest
//! ytd` figures) and `sofi_documents` (statements, listed, never downloaded).
//! Nothing here can write: the client sends GETs and the read-only
//! `Transactions` GraphQL query only.
//!
//! Provider access goes through [`Source`], the per-target seam of
//! cli-common's MCP profile (DESIGN.md §2.3); the tests run every tool
//! offline against the fixtures through it. [`LiveSource`] reads with the
//! session `sfi auth login --browser` stored in the keychain, and only when
//! a tool is called: listing the tools touches no credential. It never
//! signs in: a missing or expired session is an auth error naming that
//! command.

use std::sync::Mutex;

use pk_cli_core::{dates, CliError, CommonArgs, Money};
use pk_cli_mcp::{
    parse_args, ListArgs, Page, PageRequest, Server, ToolDef, ToolError, ToolOutput, Toolset,
};
use pk_cli_secrets::CredentialStore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::transactions::{self, Transaction};
use crate::commands::{accounts, cents_of, documents, interest, money_at, str_at, Ctx};

pub const BALANCES_TOOL: &str = "sofi_balances";
pub const TRANSACTIONS_TOOL: &str = "sofi_transactions";
pub const INTEREST_TOOL: &str = "sofi_interest";
pub const DOCUMENTS_TOOL: &str = "sofi_documents";

/// What a sign-in failure asks of the user. SoFi's password login endpoint
/// is dead (docs/api.md §2), so the profile's standard `sfi auth login`
/// remedy would send them to a dead end.
const SIGN_IN: &str = "Ask the user to run `sfi auth login --browser` in a terminal, then call \
                       the tool again. Tools never sign in or create credentials themselves";

/// Where the tools get SoFi's data: the live API, or fixtures.
#[allow(async_fn_in_trait)] // deliberate: no `Send` bound, as in `Toolset`
pub trait Source {
    /// Every account row on the login (`accounts[]`), closed ones included.
    async fn accounts(&self) -> Result<Vec<Value>, CliError>;
    /// One account's transaction list entries, every state, back to at
    /// least `since` (YYYY-MM-DD); and whether the page ceiling stopped the
    /// walk first.
    async fn transactions(
        &self,
        account_id: &str,
        since: &str,
    ) -> Result<(Vec<Value>, bool), CliError>;
    /// Every statement row.
    async fn statements(&self) -> Result<Vec<Value>, CliError>;
}

/// The live API, through the same [`Ctx`] and fetchers the commands use.
pub struct LiveSource {
    ctx: Mutex<Ctx>,
}

impl LiveSource {
    pub fn new(common: &CommonArgs, creds: CredentialStore) -> Result<Self, CliError> {
        // Quiet: stdout is the protocol. No default account: a tool reads
        // the account its arguments name, never `SFI_ACCOUNT` or the config
        // file's.
        let common = CommonArgs {
            json: true,
            quiet: true,
            ..common.clone()
        };
        Ok(Self {
            ctx: Mutex::new(Ctx::with_store(common, None, creds)?),
        })
    }

    /// Run `f` with the context, one read at a time: the client paces its
    /// own requests to SoFi, which only holds across calls made in turn.
    fn with_ctx<T>(&self, f: impl FnOnce(&Ctx) -> Result<T, CliError>) -> Result<T, CliError> {
        let ctx = self.ctx.lock().unwrap_or_else(|e| e.into_inner());
        f(&ctx)
    }
}

/// Blocking inside `async fn` is deliberate: the stdio server polls each call
/// on its own blocking thread with no Tokio reactor (pk-cli-mcp's `Toolset`
/// contract), which is where `reqwest::blocking` belongs.
impl Source for LiveSource {
    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        self.with_ctx(accounts::fetch)
    }

    async fn transactions(
        &self,
        account_id: &str,
        since: &str,
    ) -> Result<(Vec<Value>, bool), CliError> {
        self.with_ctx(|ctx| {
            let session = ctx.session()?;
            let days = transactions::lookback_days(Some(since));
            transactions::fetch_entries(ctx, &session, account_id, days)
        })
    }

    async fn statements(&self) -> Result<Vec<Value>, CliError> {
        self.with_ctx(documents::fetch_rows)
    }
}

/// The toolset `sfi mcp` serves.
pub struct SofiTools<S: Source> {
    source: S,
}

impl<S: Source> SofiTools<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }

    #[cfg(test)]
    pub fn source(&self) -> &S {
        &self.source
    }
}

/// A provider failure as a tool error; a sign-in failure names the browser
/// login.
fn tool_err(e: CliError) -> ToolError {
    match e {
        CliError::Auth(m) => ToolError::auth(auth_reason(&m)).with_fix(SIGN_IN),
        other => other.into(),
    }
}

/// Why the read was refused, without the CLI's own remedy (`— run `<built-in function bin> auth
/// login``): the fix names the one command to ask for, and a second, often
/// different, command in the same error would leave the user to pick.
fn auth_reason(m: &str) -> &str {
    [" — run `", "; run `"]
        .iter()
        .filter_map(|sep| m.find(sep))
        .min()
        .map_or(m, |cut| &m[..cut])
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

// ---- sofi_balances ----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BalancesArgs {
    /// Only this account (its name or id).
    #[serde(default)]
    pub account: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct BalancesFilter<'a> {
    account: Option<&'a str>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BalancesOut {
    /// Available balances summed over every matching account.
    pub total: String,
    /// Accounts SoFi sent with no available balance: listed, in no total.
    #[serde(skip_serializing_if = "is_zero")]
    pub unvalued: usize,
    #[serde(flatten)]
    pub page: Page<BalanceItem>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct BalanceItem {
    pub name: String,
    /// checking or savings.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apy: Option<String>,
    /// Posted balance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<String>,
    /// Masked, as SoFi shows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

// ---- sofi_transactions ------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TransactionsArgs {
    /// First day, YYYY-MM-DD. Default: Jan 1 of until's year.
    #[serde(default)]
    pub since: Option<String>,
    /// Last day, YYYY-MM-DD. Default: today.
    #[serde(default)]
    pub until: Option<String>,
    /// Only this account (its name or id).
    #[serde(default)]
    pub account: Option<String>,
    /// SoFi's category word: DEPOSIT, WITHDRAWAL, INTEREST, ... (any case).
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct TransactionsFilter<'a> {
    since: &'a str,
    until: &'a str,
    account: Option<&'a str>,
    kind: Option<&'a str>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TransactionsOut {
    pub since: String,
    pub until: String,
    /// False when an account had more history than one call reads: narrow
    /// since/until.
    pub complete: bool,
    #[serde(flatten)]
    pub page: Page<TransactionItem>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct TransactionItem {
    /// Absent when SoFi sent no readable date; such a row is in every window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Signed: money out is negative.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant: Option<String>,
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

// ---- sofi_interest ----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InterestArgs {
    /// Calendar year, e.g. 2025. Default: the current year.
    #[serde(default)]
    #[schemars(range(min = 2000, max = 2100))]
    pub year: Option<u16>,
    /// Only this account (its name or id).
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct InterestOut {
    pub year: u16,
    /// Over every matching account.
    pub total: String,
    /// Current year only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<String>,
    /// provider_estimate (SoFi's running figure) or transactions (summed
    /// payments, for a past year).
    pub source: String,
    /// False when an account had more history than one call reads.
    pub complete: bool,
    /// Interest payments with no readable date: in no total.
    #[serde(skip_serializing_if = "is_zero")]
    pub undated: usize,
    pub accounts: Vec<InterestAccount>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct InterestAccount {
    pub name: String,
    /// Absent where SoFi sent no figure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<String>,
}

// ---- sofi_documents ---------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocumentsArgs {
    /// Dated on or after, YYYY-MM-DD.
    #[serde(default)]
    pub since: Option<String>,
    /// Dated on or before, YYYY-MM-DD.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct DocumentsFilter<'a> {
    since: Option<&'a str>,
    until: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct DocumentItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    pub name: String,
    /// For `sfi documents download <id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocumentsOut {
    #[serde(flatten)]
    pub page: Page<DocumentItem>,
}

// ---- the toolset ------------------------------------------------------------

impl<S: Source> Toolset for SofiTools<S> {
    fn server(&self) -> Server {
        Server::new("sfi", env!("CARGO_PKG_VERSION"), "SoFi", "sofi").instructions(
            "SoFi access here is read-only: no tool can move money or change anything. SoFi \
             sign-in is through a browser: the command to ask for is `sfi auth login \
             --browser`. Amounts are USD decimal strings; keep every digit when adding them.",
        )
    }

    fn tools(&self) -> Vec<ToolDef> {
        vec![
            ToolDef::read(
                BALANCES_TOOL,
                "SoFi balances",
                "Lists the user's open SoFi checking and savings accounts with their balances, \
                 and the total. Use it for how much cash is at SoFi. Returns total and items \
                 with name, type, available balance and apy. Narrow with account.",
            )
            .input::<BalancesArgs>()
            .output::<BalancesOut>(),
            ToolDef::read(
                TRANSACTIONS_TOOL,
                "SoFi transactions",
                "Lists settled SoFi transactions in a date range, newest first; pending ones \
                 are left out. Use it for spending, deposits and payments over a period. Items \
                 carry date, description, signed amount, type, merchant and account. Defaults \
                 to the year to date; narrow with account or type.",
            )
            .input::<TransactionsArgs>()
            .output::<TransactionsOut>(),
            ToolDef::read(
                INTEREST_TOOL,
                "SoFi interest",
                "Totals the interest SoFi paid in a calendar year, by account. Use it for the \
                 1099-INT figure or what savings earned. Returns total, source and accounts \
                 with name and interest; the current year is SoFi's running figure, a past \
                 year the sum of its payments. Narrow with account.",
            )
            .input::<InterestArgs>()
            .output::<InterestOut>(),
            ToolDef::read(
                DOCUMENTS_TOOL,
                "SoFi statements",
                "Lists the user's SoFi bank statements, newest first, without downloading \
                 them. Use it to see which monthly statements exist. Items carry date and \
                 name; tax forms are not listed. Narrow with since/until.",
            )
            .input::<DocumentsArgs>()
            .output::<DocumentsOut>(),
        ]
    }

    async fn call(&self, name: &str, args: Value) -> Result<ToolOutput, ToolError> {
        match name {
            BALANCES_TOOL => self.balances(parse_args(args)?).await,
            TRANSACTIONS_TOOL => self.transactions(parse_args(args)?).await,
            INTEREST_TOOL => self.interest(parse_args(args)?).await,
            DOCUMENTS_TOOL => self.documents(parse_args(args)?).await,
            other => Err(ToolError::other(format!("no handler for {other}"))),
        }
    }
}

impl<S: Source> SofiTools<S> {
    async fn balances(&self, args: BalancesArgs) -> Result<ToolOutput, ToolError> {
        let account = non_empty(args.account.as_deref());
        let page = PageRequest::new(&args.list, &BalancesFilter { account })?;
        let detailed = args.list.format().is_detailed();

        let rows = self.source.accounts().await.map_err(tool_err)?;
        let open = open_accounts(&rows);
        let mut cents: i64 = 0;
        let mut unvalued = 0;
        let mut matched = Vec::new();
        for acct in pick(&open, account)? {
            let available = accounts::balance_at(acct.row, "available").map(|m| m.amount);
            match &available {
                Some(a) => cents = add_cents(cents, a, &acct.name)?,
                None => unvalued += 1,
            }
            let detail = |v: Option<String>| v.filter(|_| detailed);
            matched.push(BalanceItem {
                name: acct.name.clone(),
                kind: accounts::kind_of(acct.row),
                available,
                apy: str_at(acct.row, "formattedApy"),
                ledger: detail(accounts::balance_at(acct.row, "ledger").map(|m| m.amount)),
                number: detail(str_at(acct.row, "number")),
                id: detailed.then(|| acct.id.clone()),
            });
        }
        ToolOutput::new(&BalancesOut {
            total: Money::from_cents(cents).amount,
            unvalued,
            page: page.page(matched, "account")?,
        })
    }

    async fn transactions(&self, args: TransactionsArgs) -> Result<ToolOutput, ToolError> {
        let (since, until) = window(
            non_empty(args.since.as_deref()),
            non_empty(args.until.as_deref()),
        )?;
        let account = non_empty(args.account.as_deref());
        let kind = non_empty(args.kind.as_deref());
        let page = PageRequest::new(
            &args.list,
            &TransactionsFilter {
                since: &since,
                until: &until,
                account,
                kind,
            },
        )?;
        let detailed = args.list.format().is_detailed();

        let rows = self.source.accounts().await.map_err(tool_err)?;
        let open = open_accounts(&rows);
        let mut complete = true;
        let mut matched: Vec<TransactionItem> = Vec::new();
        for acct in pick(&open, account)? {
            let (txns, capped) = self.settled(&acct.id, &since).await?;
            complete &= !capped;
            for tx in txns {
                // An undated row stays in every window, as in `transactions
                // list`: losing a transaction is the worse failure.
                if tx
                    .date
                    .as_deref()
                    .is_some_and(|d| d < since.as_str() || d > until.as_str())
                    || kind.is_some_and(|k| {
                        !tx.kind
                            .as_deref()
                            .is_some_and(|x| x.eq_ignore_ascii_case(k))
                    })
                {
                    continue;
                }
                matched.push(TransactionItem {
                    date: tx.date,
                    description: tx.description,
                    amount: tx.amount.map(|m| m.amount),
                    kind: tx.kind,
                    merchant: tx.merchant,
                    account: acct.name.clone(),
                    id: detailed.then_some(tx.id),
                });
            }
        }
        // Newest first across accounts, undated last; a stable sort keeps
        // SoFi's order within a day.
        matched.sort_by(|a, b| b.date.cmp(&a.date));
        ToolOutput::new(&TransactionsOut {
            since,
            until,
            complete,
            page: page.page(matched, "since/until, account or type")?,
        })
    }

    async fn interest(&self, args: InterestArgs) -> Result<ToolOutput, ToolError> {
        let current = dates::today().0 as u16;
        let year = args.year.unwrap_or(current);
        if !(2000..=current).contains(&year) {
            return Err(ToolError::usage(format!(
                "year must be from 2000 to the current year ({current}); got {year}"
            )));
        }
        let account = non_empty(args.account.as_deref());

        let rows = self.source.accounts().await.map_err(tool_err)?;
        let open = open_accounts(&rows);
        let scope = pick(&open, account)?;
        if year == current {
            return provider_estimate(year, &scope);
        }

        // A past year: SoFi's running figure only covers this one, so sum
        // that year's interest payments, as `interest ytd --year` does.
        let since = format!("{year}-01-01");
        let until = format!("{year}-12-31");
        let mut out = InterestOut {
            year,
            total: String::new(),
            lifetime: None,
            source: "transactions".into(),
            complete: true,
            undated: 0,
            accounts: Vec::new(),
        };
        let mut total: i64 = 0;
        for acct in scope {
            let (txns, capped) = self.settled(&acct.id, &since).await?;
            out.complete &= !capped;
            let mut cents: i64 = 0;
            for tx in txns.iter().filter(|t| interest::is_interest(t)) {
                let Some(date) = tx.date.as_deref() else {
                    out.undated += 1;
                    continue;
                };
                if date < since.as_str() || date > until.as_str() {
                    continue;
                }
                if let Some(m) = &tx.amount {
                    cents = add_cents(cents, &m.amount, &acct.name)?;
                }
            }
            total = total
                .checked_add(cents)
                .ok_or_else(|| ToolError::upstream("the interest total overflowed"))?;
            out.accounts.push(InterestAccount {
                name: acct.name.clone(),
                interest: Some(Money::from_cents(cents).amount),
                lifetime: None,
            });
        }
        out.total = Money::from_cents(total).amount;
        ToolOutput::new(&out)
    }

    async fn documents(&self, args: DocumentsArgs) -> Result<ToolOutput, ToolError> {
        let since = date_arg("since", non_empty(args.since.as_deref()))?;
        let until = date_arg("until", non_empty(args.until.as_deref()))?;
        if let (Some(s), Some(u)) = (&since, &until) {
            if s > u {
                return Err(ToolError::usage(format!(
                    "since ({s}) is after until ({u})"
                )));
            }
        }
        let page = PageRequest::new(
            &args.list,
            &DocumentsFilter {
                since: since.as_deref(),
                until: until.as_deref(),
            },
        )?;
        let detailed = args.list.format().is_detailed();
        let ranged = since.is_some() || until.is_some();

        let rows = self.source.statements().await.map_err(tool_err)?;
        let mut matched: Vec<DocumentItem> = rows
            .iter()
            .filter_map(documents::to_document)
            // As `documents list`: an undated statement only when no range
            // is asked for.
            .filter(|d| match d.date.as_deref() {
                Some(x) => {
                    since.as_deref().is_none_or(|s| x >= s)
                        && until.as_deref().is_none_or(|u| x <= u)
                }
                None => !ranged,
            })
            .map(|d| DocumentItem {
                date: d.date,
                name: d.name,
                id: detailed.then_some(d.id),
            })
            .collect();
        matched.sort_by(|a, b| b.date.cmp(&a.date));
        ToolOutput::new(&DocumentsOut {
            page: page.page(matched, "since/until")?,
        })
    }

    /// One account's settled transactions back to `since`, mapped; and
    /// whether the walk was cut short.
    async fn settled(
        &self,
        account_id: &str,
        since: &str,
    ) -> Result<(Vec<Transaction>, bool), ToolError> {
        let (entries, capped) = self
            .source
            .transactions(account_id, since)
            .await
            .map_err(tool_err)?;
        let txns = entries
            .iter()
            .filter(|e| transactions::is_posted(e))
            .filter_map(|e| Transaction::from_entry(e, account_id))
            .collect();
        Ok((txns, capped))
    }
}

/// The current year's interest: SoFi's own running figures off the accounts
/// read, as `interest ytd` reports them.
fn provider_estimate(year: u16, scope: &[&AccountRef<'_>]) -> Result<ToolOutput, ToolError> {
    let mut total: i64 = 0;
    let mut lifetime: Option<i64> = None;
    let mut rows = Vec::new();
    for acct in scope {
        let this_year = money_at(acct.row, "estimatedInterestThisYear").map(|m| m.amount);
        let life = money_at(acct.row, "interestEarnedLifetime").map(|m| m.amount);
        if let Some(a) = &this_year {
            total = add_cents(total, a, &acct.name)?;
        }
        if let Some(a) = &life {
            lifetime = Some(add_cents(lifetime.unwrap_or(0), a, &acct.name)?);
        }
        rows.push(InterestAccount {
            name: acct.name.clone(),
            interest: this_year,
            lifetime: life,
        });
    }
    ToolOutput::new(&InterestOut {
        year,
        total: Money::from_cents(total).amount,
        lifetime: lifetime.map(|c| Money::from_cents(c).amount),
        source: "provider_estimate".into(),
        complete: true,
        undated: 0,
        accounts: rows,
    })
}

/// `cents` plus a decimal amount, exactly; an amount that is not a plain
/// decimal is an upstream surprise, never a silent zero.
fn add_cents(cents: i64, amount: &str, account: &str) -> Result<i64, ToolError> {
    cents_of(amount)
        .and_then(|c| cents.checked_add(c))
        .ok_or_else(|| {
            ToolError::upstream(format!(
                "could not add the amount `{amount}` of account {account}"
            ))
        })
}

/// One open account with the two fields every tool keys on.
struct AccountRef<'a> {
    id: String,
    /// Its nickname, else its type and masked number.
    name: String,
    row: &'a Value,
}

/// The open accounts, as `net-worth` and `transactions list` read them.
fn open_accounts(rows: &[Value]) -> Vec<AccountRef<'_>> {
    rows.iter()
        .filter(|r| accounts::is_active(r))
        .filter_map(|row| {
            let id = str_at(row, "id")?;
            let name = label(row, &id);
            Some(AccountRef { id, name, row })
        })
        .collect()
}

/// An account's name for a person: the nickname the member gave it, else
/// its type and masked number (`savings ****0000`), so two unnamed accounts
/// of one type never share a name.
fn label(row: &Value, id: &str) -> String {
    if let Some(nickname) = str_at(row, "nickname") {
        return nickname;
    }
    match (accounts::kind_of(row), str_at(row, "number")) {
        (Some(kind), Some(number)) => format!("{kind} {number}"),
        (Some(kind), None) => kind,
        (None, Some(number)) => number,
        (None, None) => id.to_string(),
    }
}

/// The accounts `wanted` names (by id, masked number, or name ignoring
/// case), or every account when it names none. An unknown name is not
/// found, listing the names that exist.
fn pick<'r, 'a>(
    all: &'r [AccountRef<'a>],
    wanted: Option<&str>,
) -> Result<Vec<&'r AccountRef<'a>>, ToolError> {
    let Some(wanted) = wanted else {
        return Ok(all.iter().collect());
    };
    let hit: Vec<&AccountRef> = all
        .iter()
        .filter(|a| {
            a.id == wanted
                || a.name.eq_ignore_ascii_case(wanted)
                || str_at(a.row, "number").as_deref() == Some(wanted)
        })
        .collect();
    if hit.is_empty() {
        let names: Vec<&str> = all.iter().map(|a| a.name.as_str()).collect();
        return Err(ToolError::not_found(format!(
            "no open SoFi account named `{wanted}`; the accounts are: {}",
            names.join(", ")
        ))
        .with_fix("Call again with one of those names"));
    }
    Ok(hit)
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// A date argument, zero-padded (`2026-1-5` is `2026-01-05`) so the string
/// comparisons that filter rows are date comparisons.
fn date_arg(name: &str, v: Option<&str>) -> Result<Option<String>, ToolError> {
    v.map(|d| {
        dates::parse_iso(d).map(dates::fmt_iso).map_err(|_| {
            ToolError::usage(format!("{name} must be a date as YYYY-MM-DD, got `{d}`"))
        })
    })
    .transpose()
}

/// The inclusive window, defaulting to the year to date.
fn window(since: Option<&str>, until: Option<&str>) -> Result<(String, String), ToolError> {
    let since = date_arg("since", since)?;
    let until = date_arg("until", until)?.unwrap_or_else(|| dates::fmt_iso(dates::today()));
    let since = since.unwrap_or_else(|| format!("{}-01-01", &until[..4]));
    if since > until {
        return Err(ToolError::usage(format!(
            "since ({since}) is after until ({until})"
        )));
    }
    Ok((since, until))
}

#[cfg(test)]
mod tests;
