//! Non-secret settings.
//!
//! One SoFi login per install (unlike `rhd`'s multi-login profiles — a SoFi
//! login is a bank account with MFA on every new device, and the household
//! runs one). The `-a/--account` flag selects among the accounts *inside*
//! that login (checking, savings, …), per SPEC v1 §1.1.
//!
//! Only non-secret preferences land on disk. Everything that authenticates —
//! password, session, device id, and any parked mid-MFA login state — lives
//! in the OS keychain under `piekstra.sfi` (see the `*_KEY` constants).

use pk_cli_secrets::CredentialStore;
use serde::{Deserialize, Serialize};

/// Binary name: keychain service (`piekstra.sfi`), config dir, env prefix.
pub const BIN: &str = "sfi";
/// Repo, for `info` and `self-update`.
pub const REPO: &str = "piekstra/sofi-cli";
/// The web app's API root. Community-documented, UNVERIFIED-LIVE — see
/// `docs/api.md` §1.
pub const API_BASE: &str = "https://www.sofi.com";

// The `SFI_ACCOUNT` env fallback for `-a/--account` is declared on the clap
// arg (main.rs, `env = "SFI_ACCOUNT"`), so it is resolved before any config
// code runs — there is no separate constant or lookup here, on purpose (see
// `resolve_account`).

/// Keychain account for the login password.
pub const PASSWORD_KEY: &str = "password";
/// Keychain account for the cached session (JSON: cookies + expiry hint).
pub const SESSION_KEY: &str = "session";
/// Keychain account for the persistent device id.
///
/// This is the value that buys device trust: SoFi ties a remembered device
/// to it, so reusing the *same* id on later logins is what gives them the
/// best chance of not re-raising the MFA challenge. Generated once and then
/// never rotated — regenerating it is indistinguishable, from the provider's
/// side, from logging in on a brand-new device.
pub const DEVICE_KEY: &str = "device";
/// Keychain account for an in-flight login parked mid-MFA.
///
/// An OTP is bound to the login attempt that requested it, so `sfi auth
/// login --code <CODE>` has to resume *that* attempt — starting a fresh
/// login and presenting the code against it would offer the code to a
/// session that never asked for one. Single-use: deleted on the next attempt
/// whether it succeeds or fails.
pub const PENDING_KEY: &str = "pending";

/// Renames the keychain service read and written, for the test suite and for
/// dogfooding the error paths: pointed at a service that holds nothing, a
/// command reads a *missing* item, which needs no user approval and fails as
/// "not logged in", where the real service would open the user's actual
/// session (and, from the ad-hoc-signed binary `cargo test` builds, raise a
/// macOS keychain prompt). It names which entry is read; it never carries a
/// session.
pub const SERVICE_ENV: &str = "SFI_KEYCHAIN_SERVICE";

/// The credential store every command uses: `piekstra.sfi`, unless
/// [`SERVICE_ENV`] names another service.
pub fn credential_store() -> CredentialStore {
    credential_store_for(std::env::var(SERVICE_ENV).ok().as_deref())
}

/// [`credential_store`]'s decision, given the variable's value, so a test
/// can check it without setting the process environment every test shares.
fn credential_store_for(service: Option<&str>) -> CredentialStore {
    match service.map(str::trim) {
        Some(s) if !s.is_empty() => CredentialStore::new(s),
        _ => CredentialStore::for_binary(BIN),
    }
}

/// On-disk, non-secret settings.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The SoFi username (usually an email address). Stored so `auth status`
    /// can report who the install is for without a network call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Default account id for `-a/--account`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

impl Config {
    /// Resolve the account id: the selection clap already resolved wins over
    /// the configured default; `None` means "whatever the provider lists".
    ///
    /// `selected` is `-a/--account`, which clap declares with `env =
    /// "SFI_ACCOUNT"` — so the flag>env precedence is already applied by the
    /// time this is called, and re-reading the environment here would be a
    /// second, divergent implementation of a rule clap owns.
    ///
    /// An **empty** selection is treated as absent: clap only skips an *unset*
    /// env var, so `SFI_ACCOUNT=""` (a common shell artifact) and `-a ""`
    /// both arrive as `Some("")`, and an empty account id can never match a
    /// real account. This is the `if !a.is_empty()` guard the old env-reading
    /// version applied, kept now at the one boundary that owns the value.
    pub fn resolve_account(&self, selected: Option<&str>) -> Option<String> {
        selected
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| self.account.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_falls_back_to_the_configured_default() {
        let cfg = Config {
            username: None,
            account: Some("1111222233".into()),
        };
        assert_eq!(cfg.resolve_account(None).as_deref(), Some("1111222233"));
        // The flag wins.
        assert_eq!(cfg.resolve_account(Some("999")).as_deref(), Some("999"));
        // Nothing configured means no selection, not a guess.
        assert_eq!(Config::default().resolve_account(None), None);
    }

    /// clap passes `SFI_ACCOUNT=""` / `-a ""` through as `Some("")`; an empty
    /// selection must read as "not provided" and fall back to the default,
    /// never match an account id of `""`.
    #[test]
    fn an_empty_selection_falls_back_rather_than_selecting_nothing() {
        let cfg = Config {
            username: None,
            account: Some("1111222233".into()),
        };
        assert_eq!(cfg.resolve_account(Some("")).as_deref(), Some("1111222233"));
        assert_eq!(Config::default().resolve_account(Some("")), None);
    }

    #[test]
    fn the_service_is_sfi_s_unless_the_variable_names_another() {
        assert_eq!(credential_store_for(None).service(), "piekstra.sfi");
        assert_eq!(credential_store_for(Some("")).service(), "piekstra.sfi");
        assert_eq!(credential_store_for(Some("  ")).service(), "piekstra.sfi");
        assert_eq!(
            credential_store_for(Some("piekstra.sfi-empty")).service(),
            "piekstra.sfi-empty"
        );
    }

    /// Secrets have fixed keychain accounts under `piekstra.sfi`; the config
    /// file has no field that could hold one.
    #[test]
    fn the_config_shape_carries_no_secret_fields() {
        let v = serde_json::to_value(Config {
            username: Some("user@example.com".into()),
            account: Some("1111222233".into()),
        })
        .unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["username", "account"]);
    }
}
