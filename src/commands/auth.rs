//! `sfi auth …` — login (including the MFA dance), status, logout, and raw
//! credential writes.
//!
//! The shape of the login flow is deliberate and is the part to preserve if
//! this file is ever rewritten:
//!
//! - **One attempt per invocation.** No loops. A loop against an MFA
//!   challenge is how a bank account gets locked.
//! - **Park, don't re-ask.** When a code is required without a TTY to prompt
//!   on, the in-flight attempt is stored and the user resumes it with
//!   `--code`. A code is bound to the attempt that requested it.
//! - **Prove before storing.** A session is only written to the keychain
//!   after a real read succeeds with it, so a login that authenticates but
//!   can't fetch anything leaves nothing broken behind.

use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserArgs, BrowserError};
use pk_cli_config::ConfigStore;
use pk_cli_core::{CliError, CommonArgs};
use pk_cli_secrets::{CredentialStore, Secret};

use crate::client::{Channel, LoginOutcome, Parked, Session, Sofi, ACCOUNTS_PATH};
use crate::config::{self, Config};

/// The bits of `auth login` this module needs, decoupled from the clap tree.
pub struct LoginInput<'a> {
    pub base: &'a LoginArgs,
    /// The supported path: harvest the session from a real browser sign-in.
    pub browser: &'a BrowserArgs,
    pub username: Option<&'a str>,
    pub code: Option<&'a str>,
    pub channel: Channel,
}

pub fn login(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    input: &LoginInput<'_>,
) -> Result<(), CliError> {
    let creds = config::credential_store();

    // The supported login: open a browser, let the owner sign in past Auth0 +
    // Cloudflare + MFA, and harvest the session cookies over CDP. The modeled
    // password-POST endpoint is dead-live (docs/api.md §2), so this is the path
    // that actually works.
    if input.browser.browser {
        let session = crate::browser::capture_session(input.browser.fresh_profile, common.quiet)?;
        return finish_browser(common, store, &mut cfg, &creds, session);
    }

    let sofi = Sofi::new()?;

    let username = resolve_username(&cfg, input, common)?;

    // A code belongs to the attempt that raised the challenge, so resume
    // *that* attempt rather than starting a fresh one: a code is bound to the
    // login that issued it.
    if let Some(code) = input.code {
        let raw = creds.get(config::PENDING_KEY)?.ok_or_else(|| {
            CliError::Usage("no login is waiting to be resumed — run `sfi auth login` first".into())
        })?;
        let parked: Parked = serde_json::from_str(raw.expose())
            .map_err(|e| CliError::Other(format!("the parked login could not be read ({e})")))?;

        let result = sofi.verify_code(&parked, code.trim());
        // Spent either way: a stale attempt must never be replayed twice.
        creds.delete(config::PENDING_KEY)?;
        let session = result?;
        return finish(
            common,
            store,
            &mut cfg,
            &creds,
            &sofi,
            &username,
            &parked.device_id,
            session,
        );
    }

    let password = resolve_password(&creds, input, common)?;

    // Reuse this install's device id if it has one. Minting a fresh id
    // presents as a brand-new device and re-raises the MFA challenge, so it
    // happens exactly once.
    let device_id = match creds.get(config::DEVICE_KEY)? {
        Some(d) => d.expose().to_string(),
        None => Sofi::new_device_id(),
    };

    match sofi.login(&username, password.expose(), &device_id, input.channel)? {
        LoginOutcome::Session(session) => finish(
            common, store, &mut cfg, &creds, &sofi, &username, &device_id, *session,
        ),
        LoginOutcome::NeedsCode { parked, hint } => {
            // Park before anything else, so even an attempt the user abandons
            // can be resumed later instead of started over — a fresh login
            // would raise a second challenge.
            creds.set(
                config::PENDING_KEY,
                &Secret::new(serde_json::to_string(&parked).unwrap_or_default()),
            )?;

            // Without a TTY there is nobody to prompt, so hand back the exact
            // command that resumes this attempt.
            if !common.interactive() {
                return Err(CliError::Auth(format!(
                    "{hint} — re-run with `sfi auth login --code <CODE>`"
                )));
            }

            eprintln!("{hint}");
            let code = prompt_line("Verification code: ")?;
            let result = sofi.verify_code(&parked, code.trim());
            creds.delete(config::PENDING_KEY)?;
            let session = result?;
            finish(
                common,
                store,
                &mut cfg,
                &creds,
                &sofi,
                &username,
                &parked.device_id,
                session,
            )
        }
    }
}

/// Prove the session works, then persist it.
///
/// The proving read happens *before* the write so a login that authenticated
/// but can't actually read the account leaves no half-working session in the
/// keychain for the next command to trip over.
#[allow(clippy::too_many_arguments)]
fn finish(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: &mut Config,
    creds: &CredentialStore,
    sofi: &Sofi,
    username: &str,
    device_id: &str,
    session: Session,
) -> Result<(), CliError> {
    let body = sofi.get(&session, &sofi.url(ACCOUNTS_PATH), &[])?;
    let accounts = crate::commands::accounts::account_rows(&body);

    creds.set(config::SESSION_KEY, &session.to_secret())?;
    creds.set(config::DEVICE_KEY, &Secret::new(device_id.to_string()))?;

    // Remember who this install is for, and adopt a sole account as the
    // default so `-a` isn't needed on a single-account login.
    cfg.username = Some(username.to_string());
    if cfg.account.is_none() && accounts.len() == 1 {
        cfg.account = accounts[0]
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
    }
    store.save(cfg)?;

    if !common.quiet {
        eprintln!(
            "logged in as {username} — {} account{} visible",
            accounts.len(),
            if accounts.len() == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

/// Persist a browser-harvested session.
///
/// `capture_session` already validated it (best-effort — the validation
/// endpoint is UNVERIFIED, so it may only confirm the bearer cookie), so this
/// just stores the session and does a best-effort account read to adopt a sole
/// account as the default. A failing/UNVERIFIED accounts read must NOT undo a
/// good login, so that read is non-fatal here (unlike `finish`, which proves a
/// password login before storing it).
fn finish_browser(
    common: &CommonArgs,
    store: &ConfigStore,
    cfg: &mut Config,
    creds: &CredentialStore,
    session: Session,
) -> Result<(), CliError> {
    creds.set(config::SESSION_KEY, &session.to_secret())?;

    // Best-effort: adopt a sole account as the default. The accounts endpoint
    // is itself UNVERIFIED, so a failure here is reported, not fatal — the
    // session is already captured and stored.
    let account_count =
        match Sofi::new().and_then(|sofi| sofi.get(&session, &sofi.url(ACCOUNTS_PATH), &[])) {
            Ok(body) => {
                let accounts = crate::commands::accounts::account_rows(&body);
                if cfg.account.is_none() && accounts.len() == 1 {
                    cfg.account = accounts[0]
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                }
                Some(accounts.len())
            }
            Err(_) => None,
        };
    store.save(cfg)?;

    if !common.quiet {
        match account_count {
            Some(n) => eprintln!(
                "logged in — session captured from the browser ({n} account{} visible)",
                if n == 1 { "" } else { "s" }
            ),
            None => eprintln!(
                "logged in — session captured from the browser (accounts read \
                 unavailable; the read endpoints are still being verified — \
                 try `sfi accounts list` or `sfi api GET <path>`)"
            ),
        }
    }
    Ok(())
}

pub fn status(
    common: &CommonArgs,
    cfg: &Config,
    account_flag: Option<&str>,
    verify: bool,
) -> Result<(), CliError> {
    let creds = config::credential_store();

    // Browser-harvested cookie session is the supported credential shape.
    let mut s = AuthStatus::new(true, false, AuthMethod::BrowserSession);
    s.username = cfg.username.clone();
    // The global `-a/--account` has to be honored here too, or `auth status`
    // reports a different account than the very next command would act on.
    s.account = cfg.resolve_account(account_flag);

    let has_password = creds.get(config::PASSWORD_KEY)?.is_some();
    s.credential_in_keychain = Some(has_password);

    match creds.get(config::SESSION_KEY)? {
        Some(raw) => {
            let session = Session::from_json(raw.expose())?;
            s.expires_at = session.expires_at_rfc3339();
            if verify {
                // Only --verify spends a request to learn whether the provider
                // still honors the session.
                let sofi = Sofi::new()?;
                let ok = sofi.get(&session, &sofi.url(ACCOUNTS_PATH), &[]).is_ok();
                s.session_valid = Some(ok);
                s.authenticated = ok;
            } else {
                s.authenticated = !session.is_expired();
            }
        }
        None => {
            s.authenticated = false;
            if verify {
                s.session_valid = Some(false);
            }
        }
    }

    s.emit(common.json);
    Ok(())
}

pub fn logout(common: &CommonArgs, store: &ConfigStore, forget: bool) -> Result<(), CliError> {
    let creds = config::credential_store();

    // The cached session and any half-finished login always go; a `logout`
    // that leaves a resumable attempt behind isn't a logout.
    creds.delete(config::SESSION_KEY)?;
    creds.delete(config::PENDING_KEY)?;

    if forget {
        creds.delete(config::PASSWORD_KEY)?;
        creds.delete(config::DEVICE_KEY)?;
        // Clearing the saved identity (username/default account) is part of
        // "forget"; a fresh default config is the empty state.
        store.save(&Config::default())?;
    }

    // Last, so a refusal (its window still open) leaves the rest done.
    let line = logout_browser(forget, || pk_cli_browser::forget_profile(config::BIN))?;
    if !common.quiet {
        eprintln!("{line}");
    }
    Ok(())
}

/// `auth logout`'s browser step. The profile a `--browser` sign-in keeps holds
/// SoFi's own cookies (its remembered device and session), so a logout removes
/// it too and the next sign-in starts signed out. The removal is passed in:
/// the binary binds it to `forget_profile(BIN)`, the tests to
/// `forget_profile_in` under a temp dir, so a test never removes the owner's
/// real profile. Returns the status line.
fn logout_browser(
    forgot_credentials: bool,
    forget_profile: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<String, CliError> {
    let removed = forget_profile()?;
    Ok(format!(
        "logged out{}{}",
        if forgot_credentials {
            " and forgot the stored credentials"
        } else {
            ""
        },
        if removed {
            "; browser profile removed"
        } else {
            ""
        }
    ))
}

pub fn set_credential(
    common: &CommonArgs,
    _store: &ConfigStore,
    _cfg: Config,
    args: &SetCredentialArgs,
) -> Result<(), CliError> {
    let creds = config::credential_store();
    if creds.get(config::PASSWORD_KEY)?.is_some() && !args.overwrite {
        return Err(CliError::Usage(
            "a password is already stored — pass --overwrite to replace it".into(),
        ));
    }
    // Headless by contract: no prompt fallback, an explicit source is required.
    let secret = args.source.read(None)?;
    if secret.is_empty() {
        return Err(CliError::Usage("the supplied password was empty".into()));
    }
    creds.set(config::PASSWORD_KEY, &secret)?;

    if !common.quiet {
        eprintln!("password stored");
    }
    Ok(())
}

fn resolve_username(
    cfg: &Config,
    input: &LoginInput<'_>,
    common: &CommonArgs,
) -> Result<String, CliError> {
    if let Some(u) = input.username {
        return Ok(u.to_string());
    }
    if let Some(u) = cfg.username.clone() {
        return Ok(u);
    }
    if common.interactive() {
        let u = prompt_line("SoFi username (email): ")?;
        if !u.trim().is_empty() {
            return Ok(u.trim().to_string());
        }
    }
    Err(CliError::Usage(
        "no username — pass `--username <EMAIL>` or set it with `sfi config set username \
         <EMAIL>`"
            .into(),
    ))
}

/// Get the password, storing it when it arrives from an explicit source so a
/// later `--code` resume can re-present it without asking again.
fn resolve_password(
    creds: &CredentialStore,
    input: &LoginInput<'_>,
    common: &CommonArgs,
) -> Result<Secret, CliError> {
    let explicit = input.base.source.stdin || input.base.source.from_env.is_some();

    if explicit {
        let secret = input.base.source.read(None)?;
        if secret.is_empty() {
            return Err(CliError::Usage("the supplied password was empty".into()));
        }
        creds.set(config::PASSWORD_KEY, &secret)?;
        return Ok(secret);
    }

    if let Some(existing) = creds.get(config::PASSWORD_KEY)? {
        return Ok(existing);
    }

    if input.base.non_interactive || !common.interactive() {
        return Err(CliError::Usage(
            "no password stored — supply one with `sfi auth login --stdin` or \
             `sfi auth set-credential --stdin`"
                .into(),
        ));
    }

    let secret = Secret::prompt("SoFi password")?;
    if secret.is_empty() {
        return Err(CliError::Usage("the supplied password was empty".into()));
    }
    creds.set(config::PASSWORD_KEY, &secret)?;
    Ok(secret)
}

fn prompt_line(label: &str) -> Result<String, CliError> {
    use std::io::{BufRead, Write};
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("reading input: {e}")))?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_parked_attempt_serializes_without_a_secret() {
        let parked = Parked {
            mfa_token: Some("tok-1".into()),
            device_id: "dev-1".into(),
            channel: Channel::Sms,
        };
        let raw = serde_json::to_string(&parked).unwrap();
        assert!(!raw.to_lowercase().contains("password"));
        assert!(raw.contains("dev-1"));
    }

    #[test]
    fn status_reports_the_family_dto() {
        let mut s = AuthStatus::new(true, true, AuthMethod::BrowserSession);
        s.username = Some("user@example.com".into());
        s.credential_in_keychain = Some(true);
        let v = s.to_json();
        assert_eq!(v["schema"], "auth-status/v1");
        assert_eq!(v["method"], "browser-session");
        assert_eq!(v["required"], true);
        // session_valid stays absent unless --verify spent a request on it.
        assert!(v.get("session_valid").is_none());
    }

    /// `finish` adopts a sole account as the default; with several it must not
    /// guess, since guessing means reading the wrong account.
    #[test]
    fn a_sole_account_becomes_the_default() {
        let accounts = [json!({"id": "1111"})];
        let picked = (accounts.len() == 1)
            .then(|| accounts[0]["id"].as_str().map(str::to_string))
            .flatten();
        assert_eq!(picked.as_deref(), Some("1111"));

        let many = [json!({"id": "1111"}), json!({"id": "2222"})];
        let picked = (many.len() == 1)
            .then(|| many[0]["id"].as_str().map(str::to_string))
            .flatten();
        assert_eq!(picked, None, "must not guess between several accounts");
    }

    /// A temp dir standing in for the per-user data dir, and the profile
    /// `forget_profile_in` looks for under it.
    fn profile_under_temp(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("sfi-logout-{tag}-{}", std::process::id()));
        // A leftover from an aborted run must not decide the test.
        let _ = std::fs::remove_dir_all(&root);
        let profile = root
            .join(format!("piekstra.{}", config::BIN))
            .join("browser-profile");
        (root, profile)
    }

    /// The logout's browser step on a temp dir through `test-util`'s
    /// `forget_profile_in`, so it never removes the owner's real profile.
    #[test]
    fn logout_removes_the_kept_browser_profile() {
        let (root, profile) = profile_under_temp("removes");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        let forget = || pk_cli_browser::forget_profile_in(&root, config::BIN);
        assert_eq!(
            logout_browser(false, forget).unwrap(),
            "logged out; browser profile removed"
        );
        assert!(!profile.exists());
        // Only the profile goes, not the directory it sits in.
        assert!(profile.parent().unwrap().exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn logout_with_no_kept_profile_still_logs_out() {
        let (root, _) = profile_under_temp("none");
        let forget = || pk_cli_browser::forget_profile_in(&root, config::BIN);
        assert_eq!(logout_browser(false, forget).unwrap(), "logged out");
        assert_eq!(
            logout_browser(true, forget).unwrap(),
            "logged out and forgot the stored credentials"
        );
    }

    #[test]
    fn logout_with_forget_says_both() {
        let (root, profile) = profile_under_temp("forget");
        std::fs::create_dir_all(&profile).unwrap();
        let forget = || pk_cli_browser::forget_profile_in(&root, config::BIN);
        assert_eq!(
            logout_browser(true, forget).unwrap(),
            "logged out and forgot the stored credentials; browser profile removed"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A profile in use refuses the logout's last step with the crate's
    /// message, which says what to close, and exit 1.
    #[test]
    fn logout_reports_a_profile_in_use() {
        let err = logout_browser(false, || {
            Err(BrowserError::ProfileInUse(
                "a Chrome (pid 7) is still running in dummy-profile".into(),
            ))
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            err.to_string(),
            "a Chrome (pid 7) is still running in dummy-profile"
        );
    }

    /// A kept profile that is a symlink needs repair: the crate refuses it,
    /// the logout says so, and neither the link nor its target goes.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_a_profile_that_needs_repair() {
        let (root, profile) = profile_under_temp("repair");
        let target = root.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &profile).unwrap();
        let err = logout_browser(false, || {
            pk_cli_browser::forget_profile_in(&root, config::BIN)
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("refusing to remove it"), "{err}");
        assert!(target.exists() && profile.symlink_metadata().is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
