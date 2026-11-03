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
    keep_config: bool,
    input: &LoginInput<'_>,
) -> Result<(), CliError> {
    let creds = config::credential_store();

    // The supported login: open a browser, let the owner sign in past Auth0 +
    // Cloudflare + MFA, and harvest the session cookies over CDP. The modeled
    // password-POST endpoint is dead-live (docs/api.md §2), so this is the path
    // that actually works.
    if input.browser.browser {
        let (fresh_profile, line) = crate::browser::scratch_profile_choice(
            input.browser.fresh_profile,
            config::service_overridden(),
        );
        if let (Some(line), false) = (line, common.quiet) {
            eprintln!("{line}");
        }
        let note = crate::browser::kept_profile_note(fresh_profile);
        return crate::browser::noting_kept_profile(note, || {
            let session = crate::browser::capture_session(fresh_profile, common.quiet)?;
            finish_browser(common, store, &mut cfg, keep_config, &creds, session)
                .map_err(BrowserError::Handler)
        });
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
            keep_config,
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
            common,
            store,
            &mut cfg,
            keep_config,
            &creds,
            &sofi,
            &username,
            &device_id,
            *session,
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
                keep_config,
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
    keep_config: bool,
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
    let left = save_signed_in_config(store, cfg, keep_config)?;

    if !common.quiet {
        if let Some(left) = left {
            eprintln!("{left}");
        }
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
    keep_config: bool,
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
    let left = save_signed_in_config(store, cfg, keep_config)?;

    if !common.quiet {
        if let Some(left) = left {
            eprintln!("{left}");
        }
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

/// Save what a sign-in learned (who this install is for, an adopted default
/// account), unless the real config is out of reach. Returns the line saying it
/// was left.
fn save_signed_in_config(
    store: &ConfigStore,
    cfg: &Config,
    keep_config: bool,
) -> Result<Option<String>, CliError> {
    if keep_config {
        return Ok(Some(format!(
            "{} is set, so the real config was left as it is",
            config::SERVICE_ENV
        )));
    }
    store.save(cfg)?;
    Ok(None)
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

    let (browser_profile, line) = browser_profile_status(config::service_overridden(), || {
        pk_cli_browser::profile_exists(config::BIN)
    });
    s.browser_profile = browser_profile;
    if let (Some(line), false) = (line, common.quiet) {
        eprintln!("{line}");
    }

    s.emit(common.json);
    Ok(())
}

/// `auth status`'s browser field: whether a `--browser` sign-in keeps a profile
/// here, not whether it is signed in. Returns the field and any line for stderr.
/// `auth status` works whatever state the CLI is in, so a profile that needs
/// repair is a warning and leaves the field out. A service `SFI_KEYCHAIN_SERVICE`
/// names is a test namespace, so while it is set nothing is read about the real
/// profile and the field is left out too.
///
/// The check is passed in: the binary binds it to `profile_exists(BIN)`, the
/// tests to `profile_exists_in` under a temp dir, so a test never reads the
/// owner's real data dir.
fn browser_profile_status(
    service_overridden: bool,
    exists: impl FnOnce() -> Result<bool, BrowserError>,
) -> (Option<bool>, Option<String>) {
    if service_overridden {
        return (
            None,
            Some(format!(
                "{} is set, so the real browser profile is not reported",
                config::SERVICE_ENV
            )),
        );
    }
    match exists() {
        Ok(kept) => (Some(kept), None),
        Err(e) => (None, Some(format!("warning: {e}"))),
    }
}

pub fn logout(
    common: &CommonArgs,
    store: &ConfigStore,
    forget: bool,
    keep_config: bool,
) -> Result<(), CliError> {
    let creds = config::credential_store();
    let steps = logout_steps(&creds, store, forget, keep_config);
    let config_left = forget && keep_config;
    let line = run_logout(
        forget,
        config::service_overridden(),
        config_left,
        steps,
        || pk_cli_browser::forget_profile(config::BIN),
    )?;
    if !common.quiet {
        eprintln!("{line}");
    }
    Ok(())
}

/// What a logout clears before the browser profile. The cached session and any
/// half-finished login always go; a `logout` that leaves a resumable attempt
/// behind isn't a logout. Nothing here parses the config, so a file that can't be
/// parsed stops nothing, and `--forget` overwrites it.
fn logout_steps<'a>(
    creds: &'a CredentialStore,
    store: &'a ConfigStore,
    forget: bool,
    keep_config: bool,
) -> Vec<LogoutStep<'a>> {
    let delete = |key: &'static str| -> Box<dyn FnOnce() -> Result<(), CliError> + 'a> {
        Box::new(move || creds.delete(key).map(drop))
    };
    let mut steps: Vec<LogoutStep<'a>> = vec![
        ("the session", delete(config::SESSION_KEY)),
        ("the parked login", delete(config::PENDING_KEY)),
    ];
    if forget {
        steps.push(("the stored password", delete(config::PASSWORD_KEY)));
        steps.push(("the device id", delete(config::DEVICE_KEY)));
        // Clearing the saved identity (username/default account) is part of
        // "forget"; a fresh default config is the empty state.
        if !keep_config {
            steps.push((
                "the saved settings",
                Box::new(|| store.save(&Config::default())),
            ));
        }
    }
    steps
}

/// One step of `auth logout` before the browser profile: what it clears, and the
/// call that clears it.
type LogoutStep<'a> = (&'static str, Box<dyn FnOnce() -> Result<(), CliError> + 'a>);

/// Runs `auth logout`. Every step is attempted, the browser profile last, even
/// when an earlier one fails: a logout that stops early leaves things behind for
/// no reason. Returns the status line, or an error saying what was cleared and
/// what remains, with the first failure's exit code.
///
/// The profile a `--browser` sign-in keeps is a full Chrome profile: SoFi's own
/// cookies (its remembered device and session), and browsing history with full
/// URLs, the HTTP cache and site storage, which Chrome's cookie encryption does
/// not cover. So a logout removes it too, and the next sign-in starts signed out.
/// The removal is passed in: the binary binds it to `forget_profile(BIN)`, the
/// tests to `forget_profile_in` under a temp dir, so a test never removes the
/// owner's real profile.
///
/// [`config::SERVICE_ENV`] moves the keychain but not the profile, so while it is set
/// (`service_overridden`) the keychain cleared here is not the real one. The real
/// profile is left alone, and the line says so.
fn run_logout(
    forgot_credentials: bool,
    service_overridden: bool,
    config_left: bool,
    steps: Vec<LogoutStep<'_>>,
    forget_profile: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<String, CliError> {
    let mut cleared = Vec::new();
    let mut remains: Vec<(&str, CliError)> = Vec::new();
    for (what, step) in steps {
        match step() {
            Ok(()) => cleared.push(what),
            Err(e) => remains.push((what, e)),
        }
    }
    const PROFILE: &str = "the browser profile";
    let mut removed = false;
    if !service_overridden {
        match forget_profile() {
            Ok(there_was_one) => {
                removed = there_was_one;
                if removed {
                    cleared.push(PROFILE);
                }
            }
            Err(e) => remains.push((PROFILE, e.into())),
        }
    }
    let left_alone = if service_overridden {
        format!(
            "{} is set, so the real browser profile{} left in place",
            config::SERVICE_ENV,
            if config_left {
                " and config were"
            } else {
                " was"
            }
        )
    } else {
        String::new()
    };
    let forgot = if forgot_credentials {
        " and forgot the stored credentials"
    } else {
        ""
    };
    if remains.is_empty() {
        return Ok(if service_overridden {
            format!("logged out{forgot}; {left_alone}")
        } else if removed {
            format!("logged out{forgot}; browser profile removed")
        } else {
            format!("logged out{forgot}")
        });
    }
    let what_remains = remains
        .iter()
        .map(|(what, e)| format!("{what}: {}", inner_message(e)))
        .collect::<Vec<_>>()
        .join("; ");
    // Only the profile left needs no `--forget`: the credentials are gone by then.
    let again = if forgot_credentials && remains.iter().any(|(what, _)| *what != PROFILE) {
        " --forget"
    } else {
        ""
    };
    let message = format!(
        "logout is incomplete. Cleared: {}. Still there: {what_remains}. {}Once that is fixed, \
         run `{} auth logout{again}` again to finish.",
        if cleared.is_empty() {
            "nothing".to_string()
        } else {
            cleared.join(", ")
        },
        if service_overridden {
            format!("{left_alone}. ")
        } else {
            String::new()
        },
        config::BIN,
    );
    let (_, first) = remains.remove(0);
    // The message covers every failure, so it must not open with the kind of the
    // first. `Keychain` and `Other`, all a real logout produces, both exit 1, so
    // the plain one keeps the code; the others with a code of their own keep it,
    // and their kind.
    Err(match first {
        CliError::Keychain(_) | CliError::Other(_) => CliError::Other(message),
        other => crate::browser::rewording(other, |_| message),
    })
}

/// An error's own message, without the kind its `Display` puts in front.
fn inner_message(err: &CliError) -> &str {
    match err {
        CliError::Usage(m)
        | CliError::Auth(m)
        | CliError::NotFound(m)
        | CliError::Upstream(m)
        | CliError::ConfirmationRequired(m)
        | CliError::Keychain(m)
        | CliError::Other(m) => m,
    }
}

pub fn set_credential(common: &CommonArgs, args: &SetCredentialArgs) -> Result<(), CliError> {
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

    /// The status's browser field on a temp dir through `test-util`'s
    /// `profile_exists_in`, so it never reads the owner's real data dir.
    #[test]
    fn auth_status_reports_the_kept_browser_profile() {
        let (root, profile) = profile_under_temp("status");
        let exists = || pk_cli_browser::profile_exists_in(&root, config::BIN);
        assert_eq!(browser_profile_status(false, exists), (Some(false), None));
        assert!(!root.exists(), "asking creates nothing");

        std::fs::create_dir_all(&profile).unwrap();
        let (field, line) = browser_profile_status(false, exists);
        assert_eq!((field, line), (Some(true), None));
        let mut status = AuthStatus::new(true, false, AuthMethod::BrowserSession);
        status.browser_profile = field;
        assert_eq!(status.to_json()["browser_profile"], true);

        // A profile that needs repair does not fail the status: the field is
        // left out, and the rest of the status still reports.
        std::fs::remove_dir(&profile).unwrap();
        std::fs::write(&profile, "x").unwrap();
        let (field, line) = browser_profile_status(false, exists);
        assert_eq!(field, None);
        assert!(line.unwrap().starts_with("warning: "));
        status.browser_profile = field;
        assert!(status.to_json().get("browser_profile").is_none());
        assert_eq!(status.to_json()["schema"], "auth-status/v1");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// While the keychain service is overridden, the status reads nothing about
    /// the real profile, and the line says so.
    #[test]
    fn auth_status_reports_nothing_about_the_real_profile_under_a_service_override() {
        let (field, line) = browser_profile_status(true, || -> Result<bool, BrowserError> {
            panic!("the real profile must not be read under a service override")
        });
        assert_eq!(field, None);
        assert_eq!(
            line.as_deref(),
            Some("SFI_KEYCHAIN_SERVICE is set, so the real browser profile is not reported")
        );
    }

    /// The logout's browser step on a temp dir through `test-util`'s
    /// `forget_profile_in`, so it never removes the owner's real profile.
    #[test]
    fn logout_removes_the_kept_browser_profile() {
        let (root, profile) = profile_under_temp("removes");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        let forget = || pk_cli_browser::forget_profile_in(&root, config::BIN);
        assert_eq!(
            run_logout(false, false, false, Vec::new(), forget).unwrap(),
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
        assert_eq!(
            run_logout(false, false, false, Vec::new(), forget).unwrap(),
            "logged out"
        );
        assert_eq!(
            run_logout(true, false, false, Vec::new(), forget).unwrap(),
            "logged out and forgot the stored credentials"
        );
    }

    #[test]
    fn logout_with_forget_says_both() {
        let (root, profile) = profile_under_temp("forget");
        std::fs::create_dir_all(&profile).unwrap();
        let forget = || pk_cli_browser::forget_profile_in(&root, config::BIN);
        assert_eq!(
            run_logout(true, false, false, Vec::new(), forget).unwrap(),
            "logged out and forgot the stored credentials; browser profile removed"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A profile in use refuses the logout's last step, exit 1. The keychain
    /// steps ran first, so the error says what they cleared, then what is left,
    /// the crate's reason and how to finish. `--forget` is not needed again.
    #[test]
    fn logout_reports_a_profile_in_use() {
        let in_use = || {
            Err(BrowserError::ProfileInUse(
                "a Chrome (pid 7) is still running in dummy-profile".into(),
            ))
        };
        let session: Vec<LogoutStep<'_>> = vec![("the session", Box::new(|| Ok(())))];
        let err = run_logout(false, false, false, session, in_use).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            err.to_string(),
            "logout is incomplete. Cleared: the session. Still there: the browser profile: a \
             Chrome (pid 7) is still running in dummy-profile. Once that is fixed, run `sfi \
             auth logout` again to finish."
        );
        let err = run_logout(true, false, false, Vec::new(), in_use).unwrap_err();
        assert!(err
            .to_string()
            .ends_with("run `sfi auth logout` again to finish."));
    }

    /// A failed keychain or config step does not stop the logout. Every later
    /// step runs, the profile included. The error reads as one message, each
    /// cause once with no kind prefix, and keeps the first failure's exit code.
    #[test]
    fn logout_attempts_every_step_when_one_fails() {
        let (root, profile) = profile_under_temp("every-step");
        std::fs::create_dir_all(&profile).unwrap();
        let later_step_ran = std::cell::Cell::new(false);
        let steps: Vec<LogoutStep<'_>> = vec![
            ("the session", Box::new(|| Ok(()))),
            (
                "the parked login",
                Box::new(|| Err(CliError::Auth("dummy first".into()))),
            ),
            (
                "the stored password",
                Box::new(|| Err(CliError::Keychain("dummy second".into()))),
            ),
            (
                "the saved settings",
                Box::new(|| {
                    later_step_ran.set(true);
                    Ok(())
                }),
            ),
        ];
        let err = run_logout(true, false, false, steps, || {
            pk_cli_browser::forget_profile_in(&root, config::BIN)
        })
        .unwrap_err();
        assert!(later_step_ran.get());
        assert!(!profile.exists(), "the profile step still ran");
        assert_eq!(err.exit_code(), 3, "the first failure's exit code");
        assert_eq!(
            err.to_string(),
            "logout is incomplete. Cleared: the session, the saved settings, the browser \
             profile. Still there: the parked login: dummy first; the stored password: dummy \
             second. Once that is fixed, run `sfi auth logout --forget` again to finish."
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A keychain failure first, as a real logout has it: exit 1, and the error
    /// does not open with a kind that names only that failure. The same under a
    /// service override: the profile is never touched, and the error says so.
    #[test]
    fn a_failed_step_under_a_service_override_still_leaves_the_profile() {
        let steps: Vec<LogoutStep<'_>> = vec![(
            "the session",
            Box::new(|| Err(CliError::Keychain("dummy".into()))),
        )];
        let err = run_logout(
            false,
            true,
            false,
            steps,
            || -> Result<bool, BrowserError> {
                panic!("the real profile must not be removed under a service override")
            },
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            err.to_string(),
            "logout is incomplete. Cleared: nothing. Still there: the session: dummy. SFI_KEYCHAIN_SERVICE \
             is set, so the real browser profile was left in place. Once that is fixed, run \
             `sfi auth logout` again to finish."
        );
    }

    /// A store for the config at `path`, and a credential store that the tests
    /// here only build: its steps are never run, so no keychain is reached.
    fn logout_stores(path: &std::path::Path) -> (CredentialStore, ConfigStore) {
        (
            CredentialStore::new("piekstra.sfi-unused-in-tests"),
            ConfigStore::new(config::BIN).with_override(Some(path.to_path_buf())),
        )
    }

    fn step_names(steps: &[LogoutStep<'_>]) -> Vec<&'static str> {
        steps.iter().map(|(what, _)| *what).collect()
    }

    /// Logout never parses the config, so a file that can't be parsed stops
    /// nothing, and `--forget` clears it. The keychain steps are left out here,
    /// and the profile step runs on a temp dir.
    #[test]
    fn logout_forget_clears_a_config_that_cannot_be_parsed() {
        let (root, _) = profile_under_temp("corrupt-config");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, "{ not json").unwrap();
        let (creds, store) = logout_stores(&path);
        assert!(store.load::<Config>().is_err(), "the file really is broken");

        let plain = logout_steps(&creds, &store, false, false);
        assert_eq!(step_names(&plain), ["the session", "the parked login"]);

        let mut steps = logout_steps(&creds, &store, true, false);
        assert_eq!(
            step_names(&steps).last(),
            Some(&"the saved settings"),
            "the config step is the one to run"
        );
        let config_step = steps.pop().unwrap();
        let line = run_logout(true, false, false, vec![config_step], || {
            pk_cli_browser::forget_profile_in(&root, config::BIN)
        })
        .unwrap();
        assert_eq!(line, "logged out and forgot the stored credentials");
        store.load::<Config>().expect("the broken file is cleared");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// While the keychain service is overridden and no `--config` was named, the
    /// real config is out of reach: `--forget` has no config step, and the line
    /// says what was left.
    #[test]
    fn logout_forget_leaves_the_real_config_under_a_service_override() {
        let (root, _) = profile_under_temp("override-config");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        std::fs::write(&path, "{ not json").unwrap();
        let (creds, store) = logout_stores(&path);
        let steps = logout_steps(&creds, &store, true, true);
        assert!(
            !step_names(&steps).contains(&"the saved settings"),
            "{:?}",
            step_names(&steps)
        );
        let never = || -> Result<bool, BrowserError> {
            panic!("the real profile must not be removed under a service override")
        };
        assert_eq!(
            run_logout(true, true, true, Vec::new(), never).unwrap(),
            "logged out and forgot the stored credentials; SFI_KEYCHAIN_SERVICE is set, so the real browser \
             profile and config were left in place"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// What a sign-in learned is saved, unless the real config is out of reach,
    /// and then the line says it was left.
    #[test]
    fn a_sign_in_leaves_the_real_config_under_a_service_override() {
        let (root, _) = profile_under_temp("signed-in-config");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("config.json");
        let (_, store) = logout_stores(&path);
        let cfg = Config {
            username: Some("user@example.com".into()),
            account: Some("dummy-account".into()),
        };

        let left = save_signed_in_config(&store, &cfg, true).unwrap();
        assert_eq!(
            left.as_deref(),
            Some("SFI_KEYCHAIN_SERVICE is set, so the real config was left as it is")
        );
        assert!(!path.exists(), "nothing was written");

        assert_eq!(save_signed_in_config(&store, &cfg, false).unwrap(), None);
        let saved: Config = store.load().unwrap();
        assert_eq!(saved.account.as_deref(), Some("dummy-account"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// While the keychain service is overridden, the real profile is out of
    /// reach: the removal is never called, and the line says it was left.
    #[test]
    fn logout_leaves_the_real_profile_under_a_service_override() {
        let never = || -> Result<bool, BrowserError> {
            panic!("the real profile must not be removed under a service override")
        };
        assert_eq!(
            run_logout(false, true, false, Vec::new(), never).unwrap(),
            "logged out; SFI_KEYCHAIN_SERVICE is set, so the real browser profile was left in place"
        );
        assert_eq!(
            run_logout(true, true, false, Vec::new(), never).unwrap(),
            "logged out and forgot the stored credentials; SFI_KEYCHAIN_SERVICE is set, so the real browser \
             profile was left in place"
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
        let err = run_logout(false, false, false, Vec::new(), || {
            pk_cli_browser::forget_profile_in(&root, config::BIN)
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("refusing to remove it"), "{err}");
        assert!(err
            .to_string()
            .contains("Still there: the browser profile: "));
        assert!(target.exists() && profile.symlink_metadata().is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
