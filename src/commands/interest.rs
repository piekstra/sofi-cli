//! `sfi interest …` — interest earned, the 1099-INT raw material.
//!
//! Two entry points off two sources:
//!
//! - **`interest ytd`** reports the provider's own running figures from the
//!   accounts endpoint — `estimatedInterestThisYear` and
//!   `interestEarnedLifetime` per account (docs/api.md §3.2), summed. This is
//!   the fast, authoritative current-year total.
//! - **`interest list`** reconstructs the **per-payment** history from
//!   transactions: SoFi pays interest as a monthly deposit, so an interest
//!   payment is a POSTED transaction whose category/description marks it as
//!   interest. This is a heuristic over the transactions BFF and is
//!   **UNVERIFIED-LIVE** — the exact `displayType` for an interest deposit is
//!   not community-documented, so `is_interest` matches on both the category
//!   and the description and every match is surfaced for the owner to confirm
//!   during the first live session (docs/api.md §3.4).

use pk_cli_core::{CliError, Money, Paged, RangeArgs};
use serde::Serialize;
use serde_json::Value;

use crate::commands::transactions::{self, Transaction};
use crate::commands::{accounts, cents_of, emit_one, money_at, str_at, Ctx};

/// The YTD/lifetime interest summary (`interest-ytd/v1`).
#[derive(Debug, Serialize)]
pub struct InterestYtd {
    /// The calendar year the `ytd` figure covers.
    pub year: u16,
    /// Interest earned so far in `year`. For the current year this is the
    /// provider's own `estimatedInterestThisYear`; for a past year it is the
    /// sum of that year's interest payments (see `source`).
    pub ytd: Money,
    /// Interest earned over the account's whole life, when the provider
    /// reports it (current-year queries only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<Money>,
    /// Where `ytd` came from: `provider_estimate` (the accounts endpoint) or
    /// `transactions` (summed interest payments for a past year).
    pub source: &'static str,
}

/// One interest payment (`interest/v1`).
#[derive(Debug, Serialize)]
pub struct Interest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

impl Interest {
    fn from_transaction(tx: &Transaction) -> Option<Self> {
        Some(Interest {
            id: tx.id.clone(),
            date: tx.date.clone(),
            amount: tx.amount.clone(),
            description: tx.description.clone(),
            account_id: tx.account_id.clone(),
        })
    }
}

/// Whether a transaction looks like an interest payment. Matches the
/// provider's category word or a description mentioning interest — a
/// deliberately generous heuristic, since under-reporting interest is the
/// worse failure for 1099-INT work. UNVERIFIED-LIVE (docs/api.md §3.4).
pub fn is_interest(tx: &Transaction) -> bool {
    let hay = format!(
        "{} {}",
        tx.kind.as_deref().unwrap_or_default(),
        tx.description.as_deref().unwrap_or_default()
    )
    .to_lowercase();
    hay.contains("interest")
}

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    let payments = interest_payments(ctx, range)?;
    transactions::warn_undated(
        ctx,
        transactions::undated_count(payments.iter().map(|p| p.date.as_deref())),
    );
    Paged::new("interest", payments).emit(ctx.common.json);
    Ok(())
}

/// Collect interest payments over a date range, newest first.
fn interest_payments(ctx: &Ctx, range: &RangeArgs) -> Result<Vec<Interest>, CliError> {
    let txns = transactions::collect(ctx, range)?;
    let mut items: Vec<Interest> = txns
        .iter()
        .filter(|t| is_interest(t))
        .filter_map(Interest::from_transaction)
        .collect();
    items.sort_by(|a, b| b.date.cmp(&a.date));
    if let Some(n) = range.limit {
        items.truncate(n as usize);
    }
    Ok(items)
}

pub fn ytd(ctx: &Ctx, year: Option<u16>) -> Result<(), CliError> {
    let current = pk_cli_core::dates::today().0 as u16;
    let year = year.unwrap_or(current);

    // A past year cannot be answered from the provider's running estimate
    // (which only tracks the current year), so it is summed from that year's
    // interest payments instead.
    if year != current {
        let range = RangeArgs {
            limit: None,
            since: Some(format!("{year}-01-01")),
            until: Some(format!("{year}-12-31")),
        };
        let payments = interest_payments(ctx, &range)?;
        let total = sum(payments.iter().filter_map(|p| p.amount.clone()))?;
        return emit(
            ctx,
            InterestYtd {
                year,
                ytd: total,
                lifetime: None,
                source: "transactions",
            },
        );
    }

    // Current year: the provider's own figures off the accounts endpoint.
    let rows = accounts::fetch(ctx)?;
    let scoped: Vec<&Value> = rows
        .iter()
        .filter(|r| accounts::is_active(r))
        .filter(|r| match &ctx.account {
            Some(a) => {
                str_at(r, "id").as_deref() == Some(a.as_str())
                    || str_at(r, "number").as_deref() == Some(a.as_str())
            }
            None => true,
        })
        .collect();
    if scoped.is_empty() {
        return Err(CliError::NotFound(
            "no matching active account — run `sfi accounts list`".into(),
        ));
    }
    let ytd = sum(scoped
        .iter()
        .filter_map(|r| money_at(r, "estimatedInterestThisYear")))?;
    let lifetime_vals: Vec<Money> = scoped
        .iter()
        .filter_map(|r| money_at(r, "interestEarnedLifetime"))
        .collect();
    let lifetime = if lifetime_vals.is_empty() {
        None
    } else {
        Some(sum(lifetime_vals.into_iter())?)
    };

    emit(
        ctx,
        InterestYtd {
            year,
            ytd,
            lifetime,
            source: "provider_estimate",
        },
    )
}

fn emit(ctx: &Ctx, dto: InterestYtd) -> Result<(), CliError> {
    emit_one("interest-ytd", &dto, ctx.common.json);
    Ok(())
}

/// Sum a series of dollar amounts in integer cents, so no float touches a
/// balance. An unparseable amount is a loud upstream error, never a silent
/// zero.
fn sum(amounts: impl Iterator<Item = Money>) -> Result<Money, CliError> {
    let mut cents: i64 = 0;
    for m in amounts {
        cents += cents_of(&m.amount).ok_or_else(|| {
            CliError::Upstream(format!(
                "could not sum an interest amount ({}) — see docs/api.md §3.2",
                m.amount
            ))
        })?;
    }
    Ok(Money::from_cents(cents))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(kind: &str, desc: &str, amount: &str, date: &str) -> Transaction {
        Transaction {
            id: format!("{date}-{amount}"),
            date: Some(date.into()),
            description: Some(desc.into()),
            amount: Some(Money::usd(amount)),
            kind: Some(kind.into()),
            merchant: None,
            state: Some("POSTED".into()),
            account_id: Some("1111".into()),
        }
    }

    #[test]
    fn interest_is_detected_by_category_or_description() {
        assert!(is_interest(&tx(
            "INTEREST",
            "Monthly payout",
            "1.23",
            "2026-06-30"
        )));
        assert!(is_interest(&tx(
            "DEPOSIT",
            "Interest earned",
            "1.23",
            "2026-06-30"
        )));
        assert!(!is_interest(&tx(
            "WITHDRAWAL",
            "Coffee shop",
            "-4.50",
            "2026-06-30"
        )));
    }

    #[test]
    fn a_payment_maps_from_its_transaction() {
        let i =
            Interest::from_transaction(&tx("INTEREST", "Payout", "1.23", "2026-06-30")).unwrap();
        assert_eq!(i.date.as_deref(), Some("2026-06-30"));
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["amount"]["amount"], "1.23");
        assert_eq!(v["account_id"], "1111");
    }

    #[test]
    fn sum_totals_in_cents_and_rejects_garbage() {
        let total =
            sum([Money::usd("1.23"), Money::usd("2.50"), Money::usd("0.02")].into_iter()).unwrap();
        assert_eq!(total.amount, "3.75");
        assert_eq!(sum(std::iter::empty()).unwrap().amount, "0.00");
        assert_eq!(
            sum([Money::usd("n/a")].into_iter())
                .unwrap_err()
                .exit_code(),
            5
        );
    }

    #[test]
    fn the_ytd_dto_is_tagged_and_carries_the_source() {
        let dto = InterestYtd {
            year: 2026,
            ytd: Money::usd("12.34"),
            lifetime: Some(Money::usd("98.76")),
            source: "provider_estimate",
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["ytd"]["amount"], "12.34");
        assert_eq!(v["lifetime"]["amount"], "98.76");
        assert_eq!(v["source"], "provider_estimate");
        // emit_one adds the schema tag; here we just pin the payload shape.
        assert_eq!(v["year"], 2026);
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new(
            "interest",
            vec![
                Interest::from_transaction(&tx("INTEREST", "Payout", "1.23", "2026-06-30"))
                    .unwrap(),
            ],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "interest-list/v1");
    }
}
