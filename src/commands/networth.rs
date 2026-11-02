//! `sfi net-worth` — the login's SoFi cash position (`net-worth/v1`).
//!
//! One figure per bank account, taken from the account's **available
//! balance** (`GET /money/api/public/v2/accounts` → `accounts[].balance`),
//! then rolled up. This is the emergency-fund input for tax-cli's
//! money-optimizer.
//!
//! The DTO is the family's `net-worth/v1` shape (`total`, `assets`,
//! `liabilities` omit-if-none, per-account `accounts[]` rows), the same
//! vocabulary `rhd net-worth` and `m1f net-worth` emit, so an asset-capturing
//! consumer needs one registry row per provider, not per-provider glue.

use pk_cli_core::{CliError, Money};
use serde::Serialize;
use serde_json::Value;

use crate::commands::accounts::{self, balance_at, kind_of};
use crate::commands::{cents_of, emit_one, str_at, Ctx};

/// The `net-worth/v1` DTO. A bank account's balance is never negative in
/// normal operation, so `liabilities` only appears in the odd overdraft case
/// where an account's available balance is below zero.
#[derive(Debug, Serialize)]
pub struct NetWorth {
    pub total: Money,
    pub assets: Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liabilities: Option<Money>,
    pub accounts: Vec<AccountRow>,
}

/// One account's slice of the rollup.
#[derive(Debug, Serialize)]
pub struct AccountRow {
    /// The account id (`net-worth/v1` uses `account_number` as the row key;
    /// SoFi's stable per-account id is what fills it).
    pub account_number: String,
    /// `checking` / `savings` — the same reading `account-list/v1` uses.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// This account's available balance.
    pub total: Money,
}

/// `explicit_account` is the `-a` flag / `SFI_ACCOUNT` env for **this
/// invocation** — never the config file's persisted default account.
///
/// That distinction is deliberate and load-bearing: every other read honoring
/// a persisted default narrows harmlessly, but this command's contract is
/// completeness, and a config default silently turning the "household" cash
/// total into one account's balance is exactly the quiet misreport the
/// honesty rules exist to prevent.
pub fn show(ctx: &Ctx, explicit_account: Option<String>) -> Result<(), CliError> {
    let rows = accounts::fetch(ctx)?;
    let active = scoped(
        rows.into_iter()
            .filter(accounts::is_active)
            .filter_map(|r| str_at(&r, "id").map(|id| (id, r)))
            .collect(),
        explicit_account.as_deref(),
    )?;

    let mut per_account = Vec::with_capacity(active.len());
    for (id, row) in &active {
        per_account.push(account_row(&id.clone(), row)?);
    }

    emit_one("net-worth", &rollup(per_account)?, ctx.common.json);
    Ok(())
}

/// Narrow the active accounts (keyed by id) to an explicit selection, or keep
/// them all. Pure, so the scoping semantics — including "no selection means
/// every account" — are pinned offline and can't drift back to honoring a
/// persisted default.
fn scoped(
    mut active: Vec<(String, Value)>,
    wanted: Option<&str>,
) -> Result<Vec<(String, Value)>, CliError> {
    if let Some(wanted) = wanted {
        active.retain(|(id, row)| id == wanted || str_at(row, "number").as_deref() == Some(wanted));
        if active.is_empty() {
            return Err(CliError::NotFound(format!(
                "no active account `{wanted}` in this login — run `sfi accounts list`"
            )));
        }
    }
    if active.is_empty() {
        return Err(CliError::Upstream(
            "SoFi returned no active accounts to value — if this login really has none that is \
             new information; otherwise the accounts shape has changed (docs/api.md §3.2)"
                .into(),
        ));
    }
    Ok(active)
}

/// Map one account row onto an [`AccountRow`]. Pure, so the mapping — including
/// the missing-balance refusal — is contract-tested offline.
fn account_row(id: &str, row: &Value) -> Result<AccountRow, CliError> {
    let total = balance_at(row, "available").ok_or_else(|| {
        // A missing balance is the failure reporting itself, not a $0 account.
        CliError::Upstream(format!(
            "account {id} carried no available balance — the shape may have changed; see \
             docs/api.md §3.2"
        ))
    })?;
    Ok(AccountRow {
        account_number: id.to_string(),
        kind: kind_of(row),
        total,
    })
}

/// Cents of precision the rollup carries. SoFi balances are whole-cent
/// dollar strings, so two decimals is exact; the sum stays in integer cents so
/// no float ever touches a balance.
fn rollup(accounts: Vec<AccountRow>) -> Result<NetWorth, CliError> {
    let mut assets: i64 = 0;
    let mut liabilities: i64 = 0;
    for row in &accounts {
        let cents = cents_of(&row.total.amount).ok_or_else(|| {
            CliError::Upstream(format!(
                "could not sum the balance for account {} — see docs/api.md §3.2",
                row.account_number
            ))
        })?;
        if cents >= 0 {
            assets += cents;
        } else {
            liabilities += -cents;
        }
    }
    Ok(NetWorth {
        total: Money::from_cents(assets - liabilities),
        assets: Money::from_cents(assets),
        liabilities: (liabilities > 0).then(|| Money::from_cents(liabilities)),
        accounts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn acct(id: &str, kind: &str, available: &str) -> Value {
        json!({
            "id": id,
            "type": kind,
            "number": format!("****{id}"),
            "balance": {"available": available, "ledger": available},
            "status": "ACTIVE"
        })
    }

    #[test]
    fn an_account_row_reports_the_available_balance() {
        let row = account_row("1111", &acct("1111", "CHECKING", "2500.00")).unwrap();
        assert_eq!(row.account_number, "1111");
        assert_eq!(row.kind.as_deref(), Some("checking"));
        assert_eq!(row.total.amount, "2500.00");
    }

    #[test]
    fn a_missing_balance_is_a_loud_upstream_error_not_zero() {
        let mut v = acct("1111", "CHECKING", "2500.00");
        v["balance"].as_object_mut().unwrap().remove("available");
        let err = account_row("1111", &v).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("1111"));
    }

    #[test]
    fn no_explicit_selection_keeps_every_account() {
        let all = vec![
            ("1111".to_string(), acct("1111", "CHECKING", "1.00")),
            ("2222".to_string(), acct("2222", "SAVING", "2.00")),
        ];
        assert_eq!(scoped(all.clone(), None).unwrap().len(), 2);
        // An explicit selection narrows to exactly that account...
        let one = scoped(all.clone(), Some("2222")).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].0, "2222");
        // ...and an unknown one is not-found (exit 4), never an empty $0 DTO.
        assert_eq!(scoped(all, Some("9999")).unwrap_err().exit_code(), 4);
    }

    #[test]
    fn no_active_accounts_is_a_loud_upstream_error() {
        assert_eq!(scoped(Vec::new(), None).unwrap_err().exit_code(), 5);
    }

    #[test]
    fn the_rollup_sums_accounts_and_omits_absent_liabilities() {
        let nw = rollup(vec![
            AccountRow {
                account_number: "1111".into(),
                kind: Some("checking".into()),
                total: Money::usd("2500.00"),
            },
            AccountRow {
                account_number: "2222".into(),
                kind: Some("savings".into()),
                total: Money::usd("10250.50"),
            },
        ])
        .unwrap();
        assert_eq!(nw.total.amount, "12750.50");
        assert_eq!(nw.assets.amount, "12750.50");
        assert!(
            nw.liabilities.is_none(),
            "no debt renders as absent, not $0"
        );
        assert_eq!(nw.accounts.len(), 2);
    }

    #[test]
    fn an_overdrawn_account_lands_in_liabilities() {
        let nw = rollup(vec![
            AccountRow {
                account_number: "1111".into(),
                kind: Some("checking".into()),
                total: Money::usd("2000.00"),
            },
            AccountRow {
                account_number: "2222".into(),
                kind: Some("checking".into()),
                total: Money::usd("-15.25"),
            },
        ])
        .unwrap();
        assert_eq!(nw.assets.amount, "2000.00");
        assert_eq!(nw.liabilities.as_ref().unwrap().amount, "15.25");
        assert_eq!(nw.total.amount, "1984.75");
    }

    #[test]
    fn an_unparseable_balance_fails_the_rollup_loudly() {
        let err = rollup(vec![AccountRow {
            account_number: "1111".into(),
            kind: None,
            total: Money::usd("n/a"),
        }])
        .unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("1111"));
    }

    // The dollar-string → cents parse (`cents_of`) is tested once in
    // `commands::tests`, its single home.

    #[test]
    fn the_dto_serializes_the_family_shape() {
        let nw = rollup(vec![AccountRow {
            account_number: "1111".into(),
            kind: Some("savings".into()),
            total: Money::usd("100.00"),
        }])
        .unwrap();
        let v = serde_json::to_value(&nw).unwrap();
        assert_eq!(v["total"]["amount"], "100.00");
        assert_eq!(v["assets"]["amount"], "100.00");
        assert_eq!(v["accounts"][0]["account_number"], "1111");
        assert_eq!(v["accounts"][0]["type"], "savings");
        assert_eq!(v["accounts"][0]["total"]["amount"], "100.00");
    }
}
