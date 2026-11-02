//! One module per command group, plus the shared [`Ctx`] they read from.

pub mod accounts;
pub mod api;
pub mod auth;
pub mod documents;
pub mod interest;
pub mod misc;
pub mod networth;
pub mod transactions;

use pk_cli_core::{output, CliError, CommonArgs, Money};
use pk_cli_secrets::CredentialStore;
use serde::Serialize;
use serde_json::Value;

use crate::client::{Session, Sofi};
use crate::config::{self, Config};

/// Read a provider money field as a [`Money`].
///
/// SoFi reports balances and interest as **strings** (`"1234.56"`); some
/// GraphQL fields (`amount.unformatted`) can be numbers. Both are handled,
/// and both stay string-decimal all the way through — never floats, per SPEC
/// v1 §1.4.
pub fn money_at(v: &Value, key: &str) -> Option<Money> {
    money_of(v.get(key)?)
}

/// Read a money value that might be a string or a JSON number.
pub fn money_of(v: &Value) -> Option<Money> {
    match v {
        Value::String(s) => Money::parse_usd(s),
        Value::Number(n) => Money::parse_usd(&n.to_string()),
        _ => None,
    }
}

/// A plain string field, absent rather than empty.
pub fn str_at(v: &Value, key: &str) -> Option<String> {
    let s = v.get(key)?.as_str()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// Convert a SoFi `createdDate.mmddyyyy` value to ISO `YYYY-MM-DD`.
///
/// The field is **unseparated** — `MMDDYYYY`, eight digits (`"07042026"`) —
/// as its name says and as the community client slices it
/// (`jjoelj/actual-bank-sync`, docs/api.md §3.4). An earlier parser demanded
/// `MM/DD/YYYY` and so dated nothing: every live row came back undated
/// (2026-09-23 capture). The slashed spelling is still accepted in case a
/// surface ever formats it. Anything else returns `None`, so a reshape
/// surfaces as a missing date rather than a scrambled one.
pub fn iso_from_mmddyyyy(raw: &str) -> Option<String> {
    let raw = raw.trim();
    // Byte-offset slicing below is only safe on ASCII; a provider value with
    // a multi-byte character must read as `None`, never panic.
    if !raw.is_ascii() {
        return None;
    }
    let (mm, dd, yyyy) = if raw.len() == 8 {
        (&raw[0..2], &raw[2..4], &raw[4..8])
    } else {
        let parts: Vec<&str> = raw.split('/').collect();
        if parts.len() != 3 {
            return None;
        }
        (parts[0], parts[1], parts[2])
    };
    if mm.len() != 2 || dd.len() != 2 || yyyy.len() != 4 {
        return None;
    }
    if ![mm, dd, yyyy]
        .iter()
        .all(|p| p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let (m, d): (u32, u32) = (mm.parse().ok()?, dd.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(format!("{yyyy}-{mm}-{dd}"))
}

/// Inclusive `--since`/`--until` test for an ISO-dated row.
pub fn date_within(date: &str, since: Option<&str>, until: Option<&str>) -> bool {
    let after_since = since.map(|s| date >= s).unwrap_or(true);
    let before_until = until.map(|u| date <= u).unwrap_or(true);
    after_since && before_until
}

/// Parse a two-decimal dollar string into signed integer cents, so a sum can
/// stay in integers and never touch a float (SPEC v1 §1.4). `None` for
/// anything that is not a plain decimal — the caller treats that as an
/// upstream surprise rather than guessing.
///
/// The **single** definition shared by the net-worth rollup and the interest
/// total (both then hand the result to [`Money::from_cents`]), so a precision
/// or sign fix lands once and the two can never disagree about the same
/// provider string.
pub fn cents_of(amount: &str) -> Option<i64> {
    let (negative, digits) = match amount.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, amount),
    };
    let (int, frac) = digits.split_once('.').unwrap_or((digits, "0"));
    if int.is_empty() || frac.len() > 2 {
        return None;
    }
    if !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let int: i64 = int.parse().ok()?;
    let frac: i64 = format!("{frac:0<2}").parse().ok()?;
    let v = int.checked_mul(100)?.checked_add(frac)?;
    Some(if negative { -v } else { v })
}

/// Emit a single (non-list) DTO per the output contract, tagged
/// `<schema>/v1`. Lists use `Paged::emit` instead.
pub fn emit_one<T: Serialize>(schema: &str, dto: &T, json_mode: bool) {
    let payload = serde_json::to_value(dto).unwrap_or(Value::Null);
    output::emit(json_mode, schema, payload, output::render);
}

/// Emit a DTO that already carries its own `schema` field (the
/// `documents/v1` profile types do), so it is not tagged twice.
pub fn emit_self_tagged<T: Serialize>(dto: &T, json_mode: bool) {
    let v = serde_json::to_value(dto).unwrap_or(Value::Null);
    if json_mode {
        output::json(&v);
    } else {
        output::render(&v);
    }
}

/// What every provider-reading command needs: the selected account (if any)
/// and a client that can talk to SoFi.
///
/// Constructing a `Ctx` performs **no** network I/O and reads no keychain
/// entry — argument validation has to be able to fail before either. The
/// session is fetched lazily by [`Ctx::session`], on first use.
pub struct Ctx {
    pub common: CommonArgs,
    /// Account id to act on, once resolved (flag > env > config default).
    pub account: Option<String>,
    pub sofi: Sofi,
    creds: CredentialStore,
}

impl Ctx {
    pub fn new(
        common: CommonArgs,
        cfg: Config,
        account_flag: Option<String>,
    ) -> Result<Self, CliError> {
        let account = cfg.resolve_account(account_flag.as_deref());
        Self::with_store(common, account, config::credential_store())
    }

    /// A context reading `creds`, with `account` already resolved (the MCP
    /// tools pass none: each call names its own).
    pub fn with_store(
        common: CommonArgs,
        account: Option<String>,
        creds: CredentialStore,
    ) -> Result<Self, CliError> {
        Ok(Ctx {
            common,
            account,
            sofi: Sofi::new()?,
            creds,
        })
    }

    /// The cached session for this install, or a pointed auth error.
    ///
    /// Deliberately does not attempt a silent password login: a login on an
    /// unrecognized device raises an MFA code that needs the account owner's
    /// phone, and doing that implicitly in the middle of an unrelated read is
    /// both surprising and a lockout risk.
    pub fn session(&self) -> Result<Session, CliError> {
        let raw = self
            .creds
            .get(config::SESSION_KEY)?
            .ok_or_else(|| CliError::Auth("no cached session — run `sfi auth login`".into()))?;
        let session = Session::from_json(raw.expose())?;
        if session.is_expired() {
            return Err(CliError::Auth(
                "the cached session has expired — run `sfi auth login`".into(),
            ));
        }
        Ok(session)
    }

    /// The account id to act on, or a usage error naming how to pick one.
    pub fn require_account(&self) -> Result<&str, CliError> {
        self.account.as_deref().ok_or_else(|| {
            CliError::Usage(
                "no account selected — pass `-a <ID>`, set one with `sfi config set account \
                 <ID>`, or run `sfi accounts list` to see them"
                    .into(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn money_reads_strings_and_numbers() {
        assert_eq!(
            money_at(&json!({"b": "1234.56"}), "b").unwrap().amount,
            "1234.56"
        );
        assert_eq!(money_of(&json!(42)).unwrap().amount, "42.00");
        assert_eq!(money_of(&json!(1.5)).unwrap().amount, "1.50");
        assert!(money_of(&json!(null)).is_none());
        assert!(money_at(&json!({"b": ""}), "b").is_none());
    }

    #[test]
    fn dates_convert_from_the_provider_format() {
        assert_eq!(
            iso_from_mmddyyyy("07/04/2026").as_deref(),
            Some("2026-07-04")
        );
        // The live wire format: unseparated MMDDYYYY.
        assert_eq!(iso_from_mmddyyyy("07042026").as_deref(), Some("2026-07-04"));
        assert_eq!(iso_from_mmddyyyy("12312025").as_deref(), Some("2025-12-31"));
        // Anything else is None, not a scrambled date.
        assert!(iso_from_mmddyyyy("2026-07-04").is_none());
        assert!(
            iso_from_mmddyyyy("20260704").is_none(),
            "YYYYMMDD is not MMDDYYYY"
        );
        assert!(iso_from_mmddyyyy("13012026").is_none());
        // Eight bytes with a multi-byte char straddling a slice offset.
        assert!(iso_from_mmddyyyy("0\u{e9}42026").is_none());
        assert!(iso_from_mmddyyyy("0704202").is_none());
        assert!(iso_from_mmddyyyy("7/4/2026").is_none());
        assert!(iso_from_mmddyyyy("").is_none());
        assert!(iso_from_mmddyyyy("aa/bb/cccc").is_none());
    }

    #[test]
    fn range_filtering_is_inclusive_on_both_ends() {
        assert!(date_within(
            "2026-07-04",
            Some("2026-07-04"),
            Some("2026-07-04")
        ));
        assert!(date_within(
            "2026-07-04",
            Some("2026-01-01"),
            Some("2026-12-31")
        ));
        assert!(!date_within("2026-07-04", Some("2026-07-05"), None));
        assert!(!date_within("2026-07-04", None, Some("2026-07-03")));
    }

    #[test]
    fn cents_of_parses_dollar_strings_and_rejects_the_rest() {
        assert_eq!(cents_of("2500.00"), Some(250_000));
        assert_eq!(cents_of("-15.25"), Some(-1525));
        assert_eq!(cents_of("10"), Some(1000));
        assert_eq!(cents_of("0.5"), Some(50));
        // The sign survives a magnitude below one dollar.
        assert_eq!(cents_of("-0.05"), Some(-5));
        assert_eq!(cents_of("1.234"), None, "more than 2 decimals");
        assert_eq!(cents_of("n/a"), None);
        assert_eq!(cents_of(""), None);
        assert_eq!(cents_of(".5"), None);
    }
}
