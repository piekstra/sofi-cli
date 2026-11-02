//! `sfi accounts …` — the bank accounts inside one login (checking, savings,
//! vaults).
//!
//! # LIVE shape (community-documented, UNVERIFIED-LIVE)
//!
//! `GET /money/api/public/v2/accounts` answers a single object:
//! `{ partyId, customerCombinedBalance{available,ledger}, accounts:[ … ] }`.
//! Each account row carries `id`, `type` (`CHECKING`/`SAVING`), a masked
//! `number`, `nickname`, `balance{available,ledger}` (string money), the APY
//! (`formattedApy`), and the interest figures (`estimatedInterestThisYear`,
//! `interestEarnedLifetime`) — see docs/api.md §3.2.

use pk_cli_core::{CliError, Money, Paged};
use serde::Serialize;
use serde_json::Value;

use crate::client::ACCOUNTS_PATH;
use crate::commands::{money_at, str_at, Ctx};

/// One bank account (`account/v1`).
#[derive(Debug, Serialize)]
pub struct Account {
    /// The account id — what the transactions GraphQL query keys off, and
    /// what `-a/--account` matches.
    pub id: String,
    /// `checking` or `savings`, lowercased from the provider's enum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The nickname the member gave the account, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// The masked account number the provider shows (never the full number in
    /// human output; it is whatever the API returns, which is already masked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    /// Available balance — the spendable figure `net-worth` sums.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available: Option<Money>,
    /// Ledger (posted) balance — present when the provider reports one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<Money>,
    /// The annual percentage yield SoFi advertises for the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apy: Option<String>,
    /// Present only when the account is closed, so an open account's row stays
    /// uncluttered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<bool>,
}

impl Account {
    pub fn from_json(v: &Value) -> Option<Self> {
        // No id means nothing downstream can address it, so the row is dropped
        // rather than emitted half-formed.
        let id = str_at(v, "id")?;
        Some(Account {
            id,
            kind: kind_of(v),
            nickname: str_at(v, "nickname"),
            number: str_at(v, "number"),
            available: balance_at(v, "available"),
            ledger: balance_at(v, "ledger"),
            apy: str_at(v, "formattedApy"),
            closed: match str_at(v, "status").as_deref() {
                Some("CLOSED") | Some("INACTIVE") => Some(true),
                _ => None,
            },
        })
    }
}

/// The provider's `type` enum (`CHECKING`, `SAVING`), lowercased and
/// singularized to the family's `checking`/`savings` vocabulary. The **one**
/// reading, shared by `account-list/v1` (`kind`) and `net-worth/v1`
/// (`accounts[].type`) so the two DTOs never disagree about one account.
pub fn kind_of(v: &Value) -> Option<String> {
    match str_at(v, "type")?.to_uppercase().as_str() {
        "CHECKING" => Some("checking".into()),
        "SAVING" | "SAVINGS" => Some("savings".into()),
        other => Some(other.to_lowercase()),
    }
}

/// Read a nested balance object's field (`balance.available`) as money.
pub fn balance_at(v: &Value, field: &str) -> Option<Money> {
    money_at(v.get("balance")?, field)
}

/// Is this account one that can currently hold value (has an id and is not
/// closed)? The valuation rollup must not sum a closed account.
pub fn is_active(v: &Value) -> bool {
    str_at(v, "id").is_some()
        && !matches!(
            str_at(v, "status").as_deref(),
            Some("CLOSED") | Some("INACTIVE")
        )
}

/// The `accounts` array out of the collection response.
pub fn account_rows(body: &Value) -> Vec<Value> {
    body.get("accounts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Fetch the raw account rows once.
pub fn fetch(ctx: &Ctx) -> Result<Vec<Value>, CliError> {
    let session = ctx.session()?;
    let body = ctx.sofi.get(&session, &ctx.sofi.url(ACCOUNTS_PATH), &[])?;
    Ok(account_rows(&body))
}

pub fn list(ctx: &Ctx) -> Result<(), CliError> {
    let rows = fetch(ctx)?;
    let accounts: Vec<Account> = rows.iter().filter_map(Account::from_json).collect();
    Paged::new("account", accounts).emit(ctx.common.json);
    Ok(())
}

pub fn get(ctx: &Ctx, id: Option<&str>) -> Result<(), CliError> {
    let wanted = match id {
        Some(i) => i.to_string(),
        None => ctx.require_account()?.to_string(),
    };
    let rows = fetch(ctx)?;
    let found = rows
        .iter()
        .filter_map(Account::from_json)
        .find(|a| a.id == wanted || a.number.as_deref() == Some(wanted.as_str()))
        .ok_or_else(|| {
            CliError::NotFound(format!(
                "no account `{wanted}` in this login — run `sfi accounts list`"
            ))
        })?;
    crate::commands::emit_one("account", &found, ctx.common.json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn checking() -> Value {
        json!({
            "id": "1111",
            "type": "CHECKING",
            "number": "****1234",
            "nickname": "Everyday",
            "balance": {"available": "2500.00", "ledger": "2480.00"},
            "formattedApy": "0.50%",
            "estimatedInterestThisYear": "12.34",
            "interestEarnedLifetime": "98.76",
            "status": "ACTIVE"
        })
    }

    #[test]
    fn maps_the_fields_the_table_reads() {
        let a = Account::from_json(&checking()).unwrap();
        assert_eq!(a.id, "1111");
        assert_eq!(a.kind.as_deref(), Some("checking"));
        assert_eq!(a.nickname.as_deref(), Some("Everyday"));
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["available"]["amount"], "2500.00");
        assert_eq!(v["ledger"]["amount"], "2480.00");
        assert_eq!(v["apy"], "0.50%");
        // An open account omits `closed` rather than emitting false.
        assert!(v.get("closed").is_none());
    }

    #[test]
    fn the_type_enum_maps_to_the_family_vocabulary() {
        assert_eq!(
            kind_of(&json!({"type": "CHECKING"})).as_deref(),
            Some("checking")
        );
        assert_eq!(
            kind_of(&json!({"type": "SAVING"})).as_deref(),
            Some("savings")
        );
        assert_eq!(
            kind_of(&json!({"type": "SAVINGS"})).as_deref(),
            Some("savings")
        );
        // An unknown type keeps the provider's own word, lowercased.
        assert_eq!(kind_of(&json!({"type": "VAULT"})).as_deref(), Some("vault"));
        assert!(kind_of(&json!({})).is_none());
    }

    #[test]
    fn a_row_without_an_id_is_dropped() {
        assert!(Account::from_json(&json!({"type": "CHECKING"})).is_none());
    }

    #[test]
    fn a_closed_account_says_so_and_is_inactive() {
        let mut v = checking();
        v["status"] = json!("CLOSED");
        let a = Account::from_json(&v).unwrap();
        assert_eq!(a.closed, Some(true));
        assert!(!is_active(&v));
        assert!(is_active(&checking()));
    }

    #[test]
    fn account_rows_are_pulled_from_the_collection_envelope() {
        let body = json!({
            "partyId": "p1",
            "customerCombinedBalance": {"available": "3000.00"},
            "accounts": [checking()]
        });
        assert_eq!(account_rows(&body).len(), 1);
        assert!(account_rows(&json!({})).is_empty());
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new("account", vec![Account::from_json(&checking()).unwrap()]);
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "account-list/v1");
        assert_eq!(v["items"][0]["id"], "1111");
    }
}
