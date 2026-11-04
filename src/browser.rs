//! `sfi auth login --browser`: the owner signs in to SoFi in a Chrome window
//! (password and the texted code), and the session is read out of it with
//! cli-common's `pk-cli-browser`. This module is SoFi's side of that: what to
//! read, how a read is confirmed, and the GraphQL header recipe taken from the
//! app's own request. Launching Chrome, the kept profile (or a scratch one with
//! `--fresh-profile`), Ctrl-C and the teardown are the crate's.
//!
//! The kept profile is a full Chrome profile, kept on disk: cookies, and browsing
//! history with full URLs including query strings, the HTTP cache and site
//! storage, which Chrome's cookie encryption does not cover and only the
//! directory's `0700` mode protects. On Linux with no desktop keyring, Chrome
//! encrypts cookies with a fixed, publicly known key, so there the session cookie
//! has only `0700` protecting it too. A `SOFI` cookie can also be left from an
//! earlier sign-in, so in a kept profile only a working validation read proves the
//! owner is in ([`confirm_outcome`]).
//!
//! # Why a browser is the supported path
//!
//! SoFi's login is an **Auth0 Universal Login** on `login.sofi.com`, fronted by
//! **Cloudflare bot protection** and **ThreatMetrix device fingerprinting**,
//! with **SMS MFA**. The modeled `POST /login-service/v1/login` this repo first
//! shipped answered **HTTP 404 live (2026-08-24)** — it does not exist. A
//! headless HTTP client cannot clear that front door, so the CLI can't log in on
//! its own. It can, however, *read* the cookies a human's own successful login
//! produced. See `docs/api.md` §2.
//!
//! # What is read, and from where
//!
//! - **Pages:** only `www.sofi.com`, the app. The crate never attaches to the
//!   login host, where Auth0, Cloudflare and ThreatMetrix run.
//! - **Cookies:** the whole `sofi.com` jar, which covers both `login.sofi.com`
//!   (the Auth0 session) and `www.sofi.com` (`SOFI`, `SOFI_SESSION`,
//!   `SOFI_R_CSRF_TOKEN`), `HttpOnly` included. The `SOFI` bearer cookie, set
//!   on the app origin only after login, is the "signed in" gate.
//!   [`Session::from_pairs`] keeps the session cookies and drops the rest.
//! - **Confirmation:** before the tab closes, the session is checked with one
//!   swappable read (`SFI_VALIDATE_PATH`, [`probe_outcome`]), so a
//!   half-finished login never yields a session that doesn't work.
//! - **The GraphQL recipe:** the first `/bff/graphql` request a `www.sofi.com`
//!   page makes, watched from the moment such a page opens; once the session
//!   is in place the tab is held open up to [`RECIPE_OBSERVE_DEADLINE`] for
//!   one. Only header **names** and the CSRF cookie's name are kept
//!   ([`derive_recipe`]); without one, the client uses its modeled defaults.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pk_cli_browser::{BrowserError, Capture, Captured, Confirm, HostRule, Launch, DEFAULT_TIMEOUT};
use pk_cli_core::CliError;

use crate::client::{
    percent_decode, validation_path, without_query, GraphqlRecipe, ReadError, Session, Sofi,
    ACCOUNTS_PATH, GRAPHQL_PATH, LOGIN_PAGE_URL, SESSION_COOKIE,
};
use crate::config::{self, SERVICE_ENV};

/// The provider's name in the crate's status lines and errors.
const LABEL: &str = "SoFi";

/// The app host: the only host whose pages the capture reads, watches and
/// closes. The sign-in page is on `login.sofi.com`, which is never touched.
const APP_HOST: &str = "www.sofi.com";

/// The domain whose whole cookie jar is read: the app host and the login host
/// both sit under it.
const JAR_DOMAIN: &str = "sofi.com";

/// How long the tab is held open for a `/bff/graphql` request once the session
/// is in place, before the session is captured without a recipe.
const RECIPE_OBSERVE_DEADLINE: Duration = Duration::from_secs(25);

/// What signing in involves, for the crate's opening status line.
const SIGN_IN_HINT: &str = "password and the texted code";

/// Printed (unless `-q`) when no `/bff/graphql` request came within
/// [`RECIPE_OBSERVE_DEADLINE`].
const NO_RECIPE_NOTE: &str = "note: no /bff/graphql request seen in the window — transactions \
     will use the modeled header defaults; if they 403, browse the app briefly and re-run \
     `sfi auth login --browser`";

/// Headers the HTTP client manages itself, excluded from a captured recipe.
const CLIENT_MANAGED_HEADERS: [&str; 11] = [
    "cookie",
    "host",
    "content-length",
    "connection",
    "content-type",
    "accept-encoding",
    "user-agent",
    ":authority",
    ":method",
    ":path",
    ":scheme",
];

/// What `sfi auth login --browser` reads: the `SOFI` cookie as the gate, the
/// `sofi.com` jar as the session, the app's first `/bff/graphql` request for
/// the recipe, and [`confirm`] before the tab closes. A capture serves one window,
/// which `window` tracks.
fn browser_capture(kept_profile: bool, window: Arc<Window>) -> Result<Capture, CliError> {
    Ok(Capture::new(LABEL, HostRule::exact(APP_HOST)?)
        .cookie(format!("https://{APP_HOST}/"), SESSION_COOKIE)
        .cookie_jar(JAR_DOMAIN)
        .optional_request(
            format!("https://{APP_HOST}{GRAPHQL_PATH}"),
            RECIPE_OBSERVE_DEADLINE,
        )
        .hint(SIGN_IN_HINT)
        .confirm(move |candidate| confirm(candidate, kept_profile, &window)))
}

/// Open the browser, wait for the owner to finish logging in, and return a
/// validated [`Session`], with the app's GraphQL header recipe when a request
/// was seen. `fresh_profile` runs this sign-in in a scratch profile instead of
/// the one sfi keeps. `quiet` suppresses the progress lines on stderr.
pub fn capture_session(fresh_profile: bool, quiet: bool) -> Result<SignedIn, BrowserError> {
    let kept_profile = runs_in_kept_profile(fresh_profile);
    let window = Arc::new(Window::default());
    let captured = pk_cli_browser::capture(
        Launch::new(config::BIN)
            .url(LOGIN_PAGE_URL)
            .fresh_profile(fresh_profile)
            .quiet(quiet),
        &browser_capture(kept_profile, Arc::clone(&window)).map_err(BrowserError::Handler)?,
        DEFAULT_TIMEOUT,
    )?;
    let session = session_from_capture(&captured).map_err(BrowserError::Handler)?;
    if !quiet {
        match &session.graphql_recipe {
            Some(recipe) => eprintln!("{}", recipe_note(recipe)),
            None => eprintln!("{NO_RECIPE_NOTE}"),
        }
    }
    Ok(SignedIn {
        session,
        unverified: window.unverified(),
    })
}

/// A finished browser sign-in.
pub struct SignedIn {
    pub session: Session,
    /// Set when the session was accepted without a read that verified it.
    pub unverified: Option<Unverified>,
}

/// Why a read could not verify a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unverified {
    pub why: String,
    pub edge_block: bool,
}

/// Whether a sign-in runs in the kept profile. The crate keeps one on unix only;
/// elsewhere every sign-in is scratch.
fn runs_in_kept_profile(fresh_profile: bool) -> bool {
    !fresh_profile && cfg!(unix)
}

/// Which profile a sign-in runs in: whether it is a scratch one, and the line to
/// print when the override, not the owner's flag, made it so. A service named by
/// [`SERVICE_ENV`] is a test namespace, so a sign-in under it must not read or
/// change the real kept profile, as `auth logout` must not remove it.
pub fn scratch_profile_choice(
    fresh_profile_flag: bool,
    service_overridden: bool,
) -> (bool, Option<String>) {
    let line = (service_overridden && !fresh_profile_flag).then(|| {
        format!(
            "{SERVICE_ENV} is set, so this sign-in uses a scratch browser profile, as with \
             --fresh-profile"
        )
    });
    (fresh_profile_flag || service_overridden, line)
}

/// The note a sign-in's failure carries: unless it ran in a scratch profile, the
/// kept profile stays on disk, possibly signed in, so the owner is told and told
/// how to remove it. `None` for a scratch profile, and where the crate keeps no
/// profile.
pub fn kept_profile_note(fresh_profile: bool) -> Option<String> {
    runs_in_kept_profile(fresh_profile).then(|| {
        format!(
            "The kept browser profile stays on disk; `{} auth logout` removes it, and clears the \
             stored session too.",
            config::BIN
        )
    })
}

/// Runs a browser sign-in, from opening the window through storing the session,
/// and adds `note` to whatever fails once Chrome may have used the profile,
/// keeping the exit code. A failure from outside the crate, such as a keychain
/// write after the capture, comes in as [`BrowserError::Handler`]. Everything but
/// the listed refusals gets the note, so a new failure path can't miss it.
///
/// The refusals come before Chrome uses the profile. They leave nothing new, and
/// the note would be false (no Chrome, so no profile) or would point at `auth
/// logout`, which refuses the same profile after clearing the stored session.
pub fn noting_kept_profile<T>(
    note: Option<String>,
    sign_in: impl FnOnce() -> Result<T, BrowserError>,
) -> Result<T, CliError> {
    sign_in().map_err(|err| {
        let before_the_profile_is_used = matches!(
            err,
            BrowserError::Invalid(_)
                | BrowserError::ChromeNotFound(_)
                | BrowserError::Profile(_)
                | BrowserError::ProfileInUse(_)
        );
        let err = CliError::from(err);
        match note {
            Some(note) if !before_the_profile_is_used => with_note(err, &note),
            _ => err,
        }
    })
}

fn with_note(err: CliError, note: &str) -> CliError {
    rewording(err, |message| {
        format!("{}. {note}", message.trim_end_matches('.'))
    })
}

/// The same kind of error, so the same exit code, with its message rewritten.
pub fn rewording(err: CliError, reword: impl FnOnce(String) -> String) -> CliError {
    match err {
        CliError::Usage(m) => CliError::Usage(reword(m)),
        CliError::Auth(m) => CliError::Auth(reword(m)),
        CliError::NotFound(m) => CliError::NotFound(reword(m)),
        CliError::Upstream(m) => CliError::Upstream(reword(m)),
        CliError::ConfirmationRequired(m) => CliError::ConfirmationRequired(reword(m)),
        CliError::Keychain(m) => CliError::Keychain(reword(m)),
        CliError::Other(m) => CliError::Other(reword(m)),
        detailed @ CliError::Detailed(_) => rewording(detailed.into_base(), reword),
    }
}

/// The session a capture hands over: the jar's session cookies, with the
/// GraphQL header recipe derived from the app's `/bff/graphql` request when
/// one was seen ([`derive_recipe`]).
fn session_from_capture(captured: &Captured) -> Result<Session, CliError> {
    // The confirm hook only lets a jar holding SOFI through, so this is the
    // session it validated.
    let mut session = session_from_jar(captured).ok_or_else(|| {
        CliError::Other(format!(
            "the browser capture came back without the {SESSION_COOKIE} cookie"
        ))
    })?;
    if let Some(request) = captured.request() {
        let headers: Vec<(&str, &str)> = request
            .headers()
            .map(|(name, value)| (name, value.expose()))
            .collect();
        session.graphql_recipe = Some(derive_recipe(&headers, &cookie_pairs(&session)));
    }
    Ok(session)
}

/// The session in a captured jar, in the order the browser lists it, or `None`
/// while the jar holds no `SOFI` bearer cookie.
fn session_from_jar(captured: &Captured) -> Option<Session> {
    Session::from_pairs(
        captured
            .jar()
            .iter()
            .map(|cookie| (cookie.name(), cookie.value().expose())),
    )
}

/// The confirm hook: validate the candidate session with one read of the
/// configured validation path against the live API before the tab closes
/// ([`confirm_with`]).
fn confirm(candidate: &Captured, kept_profile: bool, window: &Window) -> Confirm {
    confirm_with(
        candidate,
        window,
        kept_profile,
        &validation_path(),
        Sofi::new,
    )
}

/// The confirm hook with the validation read's path and the client it goes
/// through, both given, so nothing here reads the environment.
fn confirm_with(
    candidate: &Captured,
    window: &Window,
    kept_profile: bool,
    path: &str,
    client: impl FnOnce() -> Result<Sofi, CliError>,
) -> Confirm {
    let (answer, unverified) = decide(candidate, kept_profile, path, client);
    window.record(unverified);
    answer
}

/// A jar without the `SOFI` cookie keeps the wait going without building a client;
/// otherwise one read of `path` decides ([`confirm_outcome`]). A test passes a
/// literal path and a client on a loopback server.
fn decide(
    candidate: &Captured,
    kept_profile: bool,
    path: &str,
    client: impl FnOnce() -> Result<Sofi, CliError>,
) -> (Confirm, Option<Unverified>) {
    let Some(session) = session_from_jar(candidate) else {
        return (
            Confirm::NotYet(format!(
                "the {JAR_DOMAIN} jar holds no {SESSION_COOKIE} cookie yet"
            )),
            None,
        );
    };
    confirm_outcome(validate(client, &session, path), kept_profile)
}

/// What one window remembers between polls, for the store. A capture serves one
/// window.
#[derive(Default)]
struct Window {
    unverified: Mutex<Option<Unverified>>,
}

impl Window {
    fn record(&self, unverified: Option<Unverified>) {
        if unverified.is_some() {
            *self.unverified.lock().unwrap_or_else(|e| e.into_inner()) = unverified;
        }
    }

    fn unverified(&self) -> Option<Unverified> {
        self.unverified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

/// What a validation read means for the capture. Pure, so the mapping is tested
/// without a browser or a live endpoint (cli-common DESIGN.md §2.2):
///
/// - the read shows an account: capture the session;
/// - the read was refused, or a parseable answer shows no account: keep the tab open
///   and ask again next poll. A timeout names what the read was told;
/// - the read could not decide (a 429, a 5xx, no answer, an edge block's page, or a
///   2xx that is empty or not JSON), in a scratch profile: capture the session on the
///   `SOFI` cookie, unverified. That profile started empty, so the cookie came from
///   this sign-in;
/// - the same, in a kept profile: [`Confirm::Undecided`], so the crate keeps the tab
///   and the jar and asks again after its backoff. The cookie may be left from an
///   earlier sign-in, so it proves nothing without a working read, and it does not
///   survive the stop, so ending the wait could lose a finished sign-in;
/// - the validation path does not exist, in a kept profile: end the wait, since no
///   later poll can change that. A scratch profile accepts on the cookie;
/// - the client could not be built: end the wait with that error.
fn confirm_outcome(
    validated: Result<Probe, CliError>,
    kept_profile: bool,
) -> (Confirm, Option<Unverified>) {
    match validated {
        Ok(Probe::Ready) => (Confirm::Ready, None),
        Ok(Probe::NotYet { why, .. }) => (Confirm::NotYet(why), None),
        Ok(Probe::Undecided {
            reason,
            retry_after,
            ..
        }) if kept_profile => (
            Confirm::Undecided {
                reason,
                retry_after,
            },
            None,
        ),
        Ok(Probe::NoSuchPath(why)) if kept_profile => (
            Confirm::Fail(CliError::Upstream(format!(
                "{why}. The kept browser profile's {SESSION_COOKIE} cookie may be from an earlier \
                 sign-in, so it was not accepted without that read. Fix that, then retry `sfi auth \
                 login --browser` (if you signed in, there is nothing further to enter), or use \
                 `--fresh-profile`."
            ))),
            None,
        ),
        Ok(Probe::Undecided {
            reason, edge_block, ..
        }) => (
            Confirm::Ready,
            Some(Unverified {
                why: reason,
                edge_block,
            }),
        ),
        Ok(Probe::NoSuchPath(why)) => (
            Confirm::Ready,
            Some(Unverified {
                why,
                edge_block: false,
            }),
        ),
        Err(e) => (Confirm::Fail(e), None),
    }
}

/// A session a sign-in could not verify may not replace a working stored one without
/// `--overwrite` (cli-common DESIGN.md §2.2). What is stored decides.
#[derive(Debug, PartialEq, Eq)]
pub enum StoredSession {
    Absent,
    /// It can't be read, it has expired, or the provider refused it.
    Dead,
    Working,
    /// One read could not tell, so it may still work.
    CantTell,
}

/// One read of the stored session, to learn whether an unverified one may replace it.
pub fn stored_session_state(raw: Option<&str>) -> StoredSession {
    stored_state_with(raw, &validation_path(), Sofi::new)
}

fn stored_state_with(
    raw: Option<&str>,
    path: &str,
    client: impl FnOnce() -> Result<Sofi, CliError>,
) -> StoredSession {
    let Some(raw) = raw else {
        return StoredSession::Absent;
    };
    let Ok(session) = Session::from_json(raw) else {
        return StoredSession::Dead;
    };
    if session.is_expired() {
        return StoredSession::Dead;
    }
    match validate(client, &session, path) {
        Ok(Probe::Ready) => StoredSession::Working,
        Ok(Probe::NotYet {
            may_be_a_block: false,
            ..
        }) => StoredSession::Dead,
        // An edge block, a plain 403 or a read that could not decide says nothing
        // about the stored session.
        Ok(Probe::Undecided { .. })
        | Ok(Probe::NoSuchPath(_))
        | Ok(Probe::NotYet {
            may_be_a_block: true,
            ..
        })
        | Err(_) => StoredSession::CantTell,
    }
}

/// Keep a stored session that works or may work. A working one is the owner's to
/// replace (exit 2); one that could not be checked is exit 5. `why` is why the new
/// session is unverified.
pub fn refuse_replacing(stored: &StoredSession, why: &Unverified) -> Result<(), CliError> {
    let advice = edge_block_advice(why);
    let way_out = format!(
        "To replace it, run `{} auth login --browser --overwrite`",
        config::BIN
    );
    let cause = &why.why;
    match stored {
        StoredSession::Absent | StoredSession::Dead => Ok(()),
        StoredSession::Working => Err(CliError::Usage(format!(
            "this sign-in's session could not be verified ({cause}), and the stored one still \
             works, so nothing was stored and the stored one was kept. {advice}{way_out}"
        ))),
        StoredSession::CantTell => Err(CliError::Upstream(format!(
            "this sign-in's session could not be verified ({cause}), and the stored one could \
             not be checked, so nothing was stored and the stored one was kept. {advice}{way_out}"
        ))),
    }
}

/// What a message about an edge block says before it names `--overwrite`.
fn edge_block_advice(why: &Unverified) -> &'static str {
    if why.edge_block {
        "A new sign-in may not clear this, because the block is on the client rather than the \
         session. Wait or try another network. "
    } else {
        ""
    }
}

/// What a stored unverified session prints. It goes out even under `-q`.
pub fn unverified_warning(why: &Unverified) -> String {
    format!(
        "warning: this session is stored unverified: {}. {}If it does not work, run `{} auth \
         login --browser --overwrite`.",
        why.why,
        edge_block_advice(why),
        config::BIN
    )
}

/// Derive a [`GraphqlRecipe`] from an observed `/bff/graphql` request's headers
/// (name, value) and the session's cookies. Pure, so it is tested without a
/// live browser.
///
/// Records header **names** only, plus which session cookie the CSRF header's
/// value equals (raw or URL-decoded) — never the CSRF value itself.
fn derive_recipe(headers: &[(&str, &str)], cookies: &[(String, String)]) -> GraphqlRecipe {
    let mut header_names: Vec<String> = headers
        .iter()
        .map(|(name, _)| name.to_lowercase())
        .filter(|name| !CLIENT_MANAGED_HEADERS.contains(&name.as_str()))
        .collect();
    header_names.sort();
    header_names.dedup();

    // The CSRF-carrying header, and which cookie its value came from.
    let mut csrf_header = None;
    let mut csrf_cookie = None;
    let mut csrf_url_decoded = false;
    if let Some((name, value)) = headers
        .iter()
        .find(|(name, _)| name.to_lowercase().contains("csrf"))
    {
        csrf_header = Some(name.to_lowercase());
        for (cookie_name, cookie_value) in cookies {
            if cookie_value == value {
                csrf_cookie = Some(cookie_name.clone());
                csrf_url_decoded = false;
                break;
            }
            if percent_decode(cookie_value) == *value {
                csrf_cookie = Some(cookie_name.clone());
                csrf_url_decoded = true;
                break;
            }
        }
    }

    GraphqlRecipe {
        header_names,
        csrf_header,
        csrf_cookie,
        csrf_url_decoded,
    }
}

/// The status line for a captured recipe: how many headers, and the CSRF
/// mapping when there is one. Names only, never a value.
fn recipe_note(recipe: &GraphqlRecipe) -> String {
    let csrf = match (&recipe.csrf_header, &recipe.csrf_cookie) {
        (Some(header), Some(cookie)) => format!(
            "; csrf header `{header}` from cookie `{cookie}`{}",
            if recipe.csrf_url_decoded {
                ", url-decoded"
            } else {
                ""
            }
        ),
        _ => String::new(),
    };
    format!(
        "captured the /bff/graphql header recipe ({} headers{csrf})",
        recipe.header_names.len()
    )
}

/// A session's cookies as owned `(name, value)` pairs, for matching a captured
/// CSRF header value to its source cookie. Delegates to `Session::cookie_pairs`
/// — the one parser of that wire format — rather than re-splitting.
fn cookie_pairs(session: &Session) -> Vec<(String, String)> {
    session
        .cookie_pairs()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

/// What a validation read of a captured session means.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// The answer shows an account.
    Ready,
    /// Refused, or a parseable answer with no account: keep waiting. `may_be_a_block`
    /// is a plain 403, which could be a bot check as well as an invalid session.
    NotYet { why: String, may_be_a_block: bool },
    /// The read could not decide. The reason holds fixed parts only.
    Undecided {
        reason: String,
        retry_after: Option<Duration>,
        edge_block: bool,
    },
    /// A 404: the validation endpoint, itself unverified, is not there.
    NoSuchPath(String),
}

/// Classify a validation read. Pure, so the decision is tested without a live
/// endpoint. A reason holds the path without its query, a status and fixed words,
/// never the answer's body or the provider's own message.
///
/// The validation endpoint (`validation_path`) is swappable because it was
/// UNVERIFIED-LIVE when this was written, so a 404 must not block a capture
/// whose bearer cookie is present in a scratch profile.
fn probe_outcome(res: &Result<serde_json::Value, ReadError>, path: &str) -> Probe {
    let shown = without_query(path);
    let read = format!("the validation read {shown}");
    let undecided =
        |reason: String, retry_after: Option<Duration>, edge_block: bool| Probe::Undecided {
            reason,
            retry_after,
            edge_block,
        };
    let refused = |why: String, may_be_a_block: bool| Probe::NotYet {
        why,
        may_be_a_block,
    };
    match res {
        Ok(body) if shows_an_account(body, path) => Probe::Ready,
        // `parse_json` reads an empty body as null, so a literal null reads the same.
        Ok(serde_json::Value::Null) => {
            undecided(format!("{read} answered with nothing in it"), None, false)
        }
        Ok(_) => refused(format!("{read} answered with no account in it"), false),
        Err(ReadError::EdgeBlock {
            status,
            retry_after,
        }) => undecided(
            format!("{read} answered HTTP {status} with a page that is possibly a bot check or edge block"),
            *retry_after,
            true,
        ),
        Err(ReadError::Inconclusive {
            status,
            retry_after,
            ..
        }) => undecided(format!("{read} answered HTTP {status}"), *retry_after, false),
        Err(ReadError::NoAnswer(_)) => undecided(format!("{read} got no answer"), None, false),
        Err(ReadError::NotJson(_)) => {
            undecided(format!("{read} answered with no JSON in it"), None, false)
        }
        Err(ReadError::Forbidden(e)) => refused(format!("{read} was refused: {e}"), true),
        Err(ReadError::Rejected { status, .. }) => {
            refused(format!("{read} answered HTTP {status}"), false)
        }
        // HTML-where-JSON-expected, a login redirect or a 401 map to Auth. That text
        // is fixed, with a status and a URL without its query.
        Err(ReadError::Failed(CliError::Auth(why))) => {
            refused(format!("{read} was refused: {why}"), false)
        }
        Err(ReadError::Failed(CliError::NotFound(_))) => Probe::NoSuchPath(format!(
            "{read} returned 404 — that endpoint is unverified (set SFI_VALIDATE_PATH to a known \
             read)"
        )),
        Err(ReadError::Failed(_)) => undecided(format!("{read} could not decide"), None, false),
    }
}

/// Whether a read's answer shows an account. The accounts read (docs/api.md §3.2)
/// says so by value: a non-empty `accounts` list, or a non-empty `partyId` for a
/// member with no account open. A path `SFI_VALIDATE_PATH` names has no known shape,
/// so a non-empty object or array counts there.
pub fn shows_an_account(body: &serde_json::Value, path: &str) -> bool {
    use serde_json::Value;
    if path == ACCOUNTS_PATH {
        let listed = matches!(body.get("accounts"), Some(Value::Array(rows)) if !rows.is_empty());
        let party = matches!(body.get("partyId"), Some(Value::String(id)) if !id.trim().is_empty());
        return listed || party;
    }
    match body {
        Value::Object(fields) => !fields.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => false,
    }
}

/// Read `path` with a captured session, through the client `client` builds,
/// and classify the answer. The client's own request timeout bounds it, which
/// the confirm hook relies on.
fn validate(
    client: impl FnOnce() -> Result<Sofi, CliError>,
    session: &Session,
    path: &str,
) -> Result<Probe, CliError> {
    let sofi = client()?;
    let res = sofi.read(session, &sofi.url(path), &[]);
    Ok(probe_outcome(&res, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::Instant;

    use pk_cli_browser::{CapturedRequest, JarCookie};
    use serde_json::json;

    /// The definition `pk-cli-browser` checks before Chrome starts, checked
    /// here offline: the SOFI cookie and the GraphQL URL on the app host, and
    /// a jar domain the app host is under.
    #[test]
    fn the_browser_capture_is_well_formed() {
        let capture = browser_capture(false, Arc::new(Window::default())).unwrap();
        capture.validate().unwrap();
        assert_eq!(capture.label(), "SoFi");
    }

    /// The capture reads the host the client calls, and the window opens on
    /// the login host, which the capture never reads but whose cookies the
    /// jar takes.
    #[test]
    fn the_app_host_is_the_api_host_and_the_login_page_is_off_it() {
        assert_eq!(format!("https://{APP_HOST}"), config::API_BASE);
        let app = HostRule::exact(APP_HOST).unwrap();
        let jar = HostRule::domain(JAR_DOMAIN).unwrap();
        assert!(
            !app.matches_url(LOGIN_PAGE_URL),
            "the login page is never read"
        );
        assert!(
            jar.matches_url(LOGIN_PAGE_URL),
            "its cookies are in the jar"
        );
        assert!(app.matches_url(&format!("https://{APP_HOST}{GRAPHQL_PATH}")));
    }

    /// Only `www.sofi.com` pages are read, watched and closed: a real host
    /// check, never a substring of the URL.
    #[test]
    fn only_app_pages_are_read() {
        let app = HostRule::exact(APP_HOST).unwrap();
        for (url, want) in [
            ("https://www.sofi.com/my/money/", true),
            ("https://www.sofi.com:443/my/banking/accounts/", true),
            ("https://login.sofi.com/u/login", false),
            ("https://sofi.com/", false),
            ("http://www.sofi.com/my/money/", false),
            ("https://evil.example/?x=www.sofi.com", false),
            ("https://www.sofi.com.evil.example/app", false),
            ("https://www.sofi.com@evil.example/", false),
        ] {
            assert_eq!(app.matches_url(url), want, "{url}");
        }
    }

    /// The jar takes cookies on `sofi.com` and every host under it, label for
    /// label. (A cookie listed as `.sofi.com` has its leading dot trimmed by
    /// the crate before this match.)
    #[test]
    fn sofi_domains_are_recognized_and_confusables_rejected() {
        let jar = HostRule::domain(JAR_DOMAIN).unwrap();
        for host in [
            "sofi.com",
            "www.sofi.com",
            "login.sofi.com",
            "WWW.SoFi.com.",
        ] {
            assert!(jar.matches_host(host), "{host}");
        }
        for host in [
            "sofi.com.evil.example",
            "notsofi.com",
            "sofi.co",
            "accounts.google.com",
            "xn--sof-xna.com",
            "com",
        ] {
            assert!(!jar.matches_host(host), "{host}");
        }
    }

    /// Before the app redirect the jar holds SoFi cookies but no SOFI bearer:
    /// not a session yet.
    #[test]
    fn a_jar_without_the_bearer_is_not_a_session() {
        let jar = [
            ("SOFI_R_CSRF_TOKEN", "dummy-csrf"),
            ("auth0", "dummy-auth0"),
        ];
        assert!(Session::from_pairs(jar).is_none());
        assert!(Session::from_pairs(Vec::<(&str, &str)>::new()).is_none());
    }

    /// A signed-in jar across both hosts becomes the session: the four session
    /// cookies are kept in the jar's order, the CSRF token is extracted, and
    /// the login host's Auth0 cookie is dropped.
    #[test]
    fn a_jar_across_both_domains_becomes_the_session() {
        let jar = [
            ("auth0", "dummy-auth0"),
            ("SOFI", "dummy-bearer"),
            ("SOFI_SESSION", "dummy-session"),
            ("SOFI_LOGIN", "1"),
            ("SOFI_R_CSRF_TOKEN", "dummy-csrf"),
            ("_ga", "dummy-analytics"),
        ];
        let session = Session::from_pairs(jar).expect("SOFI present");
        assert_eq!(
            session.cookie,
            "SOFI=dummy-bearer; SOFI_SESSION=dummy-session; SOFI_LOGIN=1; \
             SOFI_R_CSRF_TOKEN=dummy-csrf"
        );
        assert_eq!(session.csrf_token.as_deref(), Some("dummy-csrf"));
        assert!(session.graphql_recipe.is_none());
    }

    /// The accounts read shows an account by value: a list holding one, or a party id
    /// with something in it. The field being there is not enough.
    #[test]
    fn the_accounts_read_tests_the_fields_value() {
        for body in [
            include_str!("../tests/fixtures/accounts.json").to_string(),
            json!({"accounts": [{"id": "dummy"}]}).to_string(),
            json!({"partyId": "dummy", "accounts": []}).to_string(),
        ] {
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                probe_outcome(&Ok(body.clone()), ACCOUNTS_PATH),
                Probe::Ready,
                "{body}"
            );
        }
        for body in [
            json!({}),
            json!([]),
            json!(true),
            json!(0),
            json!("dummy"),
            json!({"accounts": []}),
            json!({"accounts": null}),
            json!({"accounts": "dummy"}),
            json!({"partyId": ""}),
            json!({"partyId": null}),
            json!({"partyId": 1}),
            json!({"error": "dummy"}),
            json!({"redirectUrl": "/login", "success": false}),
        ] {
            let probe = probe_outcome(&Ok(body.clone()), ACCOUNTS_PATH);
            assert_eq!(
                probe,
                Probe::NotYet {
                    why: format!(
                        "the validation read {ACCOUNTS_PATH} answered with no account in it"
                    ),
                    may_be_a_block: false,
                },
                "{body}"
            );
        }
    }

    /// `SFI_VALIDATE_PATH` names a read with no known shape, so anything in it counts.
    #[test]
    fn another_validation_path_accepts_a_non_empty_answer() {
        assert_eq!(
            probe_outcome(&Ok(json!({"dummy": null})), "/x"),
            Probe::Ready
        );
        assert_eq!(probe_outcome(&Ok(json!(["dummy"])), "/x"), Probe::Ready);
        assert!(matches!(
            probe_outcome(&Ok(json!({})), "/x"),
            Probe::NotYet { .. }
        ));
    }

    #[test]
    fn probe_not_yet_on_an_auth_answer() {
        // HTML/login-redirect/401 all surface as CliError::Auth.
        assert_eq!(
            probe_outcome(&Err(CliError::Auth("html login page".into()).into()), "/x"),
            Probe::NotYet {
                why: "the validation read /x was refused: html login page".into(),
                may_be_a_block: false
            }
        );
    }

    #[test]
    fn probe_names_a_missing_path_and_keeps_a_reason_to_fixed_parts() {
        // The default validation endpoint is swappable, so a 404 must not
        // block a capture whose bearer cookie is present.
        match probe_outcome(&Err(CliError::NotFound("404".into()).into()), "/accounts") {
            Probe::NoSuchPath(why) => {
                assert!(why.contains("/accounts"));
                assert!(why.contains("SFI_VALIDATE_PATH"));
            }
            other => panic!("expected NoSuchPath, got {other:?}"),
        }
        let detail = || CliError::Upstream("dummy provider detail".into());
        for (res, said) in [
            (ReadError::NoAnswer(detail()), "got no answer"),
            (ReadError::NotJson(detail()), "no JSON in it"),
            (ReadError::Failed(detail()), "could not decide"),
        ] {
            let Probe::Undecided { reason, .. } = probe_outcome(&Err(res), "/x?state=dummy") else {
                panic!("{said}: expected Undecided");
            };
            assert!(reason.contains(said), "{reason}");
            assert!(reason.starts_with("the validation read /x "), "{reason}");
            assert!(!reason.contains("dummy"), "{reason}");
        }
    }

    /// The confirm hook's mapping: a working read captures, a signed-out answer keeps
    /// the tab open with the reason, a read that can't decide captures unverified in a
    /// scratch profile and is `Undecided` in a kept one, and a client that cannot be
    /// built ends the wait with its own error.
    #[test]
    fn the_confirm_mapping_follows_the_probe() {
        for kept_profile in [false, true] {
            let (answer, note) = confirm_outcome(Ok(Probe::Ready), kept_profile);
            assert!(matches!(answer, Confirm::Ready), "{answer:?}");
            assert_eq!(note, None);

            let refused = Probe::NotYet {
                why: "dummy refusal".into(),
                may_be_a_block: false,
            };
            let (answer, note) = confirm_outcome(Ok(refused), kept_profile);
            assert!(
                matches!(&answer, Confirm::NotYet(reason) if reason == "dummy refusal"),
                "{answer:?}"
            );
            assert_eq!(note, None);

            let (answer, note) =
                confirm_outcome(Err(CliError::Other("no client".into())), kept_profile);
            match answer {
                Confirm::Fail(e) => {
                    assert_eq!(e.exit_code(), 1);
                    assert_eq!(e.to_string(), "no client");
                }
                other => panic!("expected Fail, got {other:?}"),
            }
            assert_eq!(note, None);
        }

        let undecided = |edge_block| Probe::Undecided {
            reason: "why".into(),
            retry_after: Some(Duration::from_secs(120)),
            edge_block,
        };
        let (answer, note) = confirm_outcome(Ok(undecided(true)), false);
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert_eq!(
            note,
            Some(Unverified {
                why: "why".into(),
                edge_block: true
            })
        );
        let (answer, note) = confirm_outcome(Ok(undecided(false)), true);
        match answer {
            Confirm::Undecided {
                reason,
                retry_after,
                ..
            } => {
                assert_eq!(reason, "why");
                assert_eq!(retry_after, Some(Duration::from_secs(120)));
            }
            other => panic!("expected Undecided, got {other:?}"),
        }
        assert_eq!(note, None);
    }

    /// A 404 captures unverified in a scratch profile, naming SFI_VALIDATE_PATH.
    #[test]
    fn a_404_in_a_scratch_profile_is_stored_unverified() {
        let res = Err(CliError::NotFound("404".into()).into());
        let (answer, note) = confirm_outcome(Ok(probe_outcome(&res, "/x")), false);
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        let note = note.expect("the reason is recorded");
        assert!(note.why.contains("SFI_VALIDATE_PATH"), "{note:?}");
        assert!(!note.edge_block);
    }

    #[test]
    fn a_recipe_records_header_names_and_the_csrf_cookie_source() {
        // The app sent a csrf header whose value is the SOFI_R_CSRF_TOKEN
        // cookie URL-decoded (the classic percent-encoded-base64 case). The
        // crate hands headers over lowercased and sorted by name.
        let headers = [
            ("apollographql-client-name", "banking-accounts-ui"),
            ("content-type", "application/json"),
            ("cookie", "SOFI=... (browser-managed, must be dropped)"),
            ("origin", "https://www.sofi.com"),
            ("x-csrf-token", "ab/cd+ef="),
        ];
        let cookies = vec![
            ("SOFI".to_string(), "bearer".to_string()),
            (
                "SOFI_R_CSRF_TOKEN".to_string(),
                "ab%2Fcd%2Bef%3D".to_string(),
            ),
        ];
        let r = derive_recipe(&headers, &cookies);
        // Browser-managed headers are excluded.
        assert!(!r.header_names.contains(&"cookie".to_string()));
        assert!(!r.header_names.contains(&"content-type".to_string()));
        // The app headers are recorded (lowercased).
        assert!(r.header_names.contains(&"x-csrf-token".to_string()));
        assert!(r.header_names.contains(&"origin".to_string()));
        // The CSRF recipe: real header name, source cookie, url-decoded.
        assert_eq!(r.csrf_header.as_deref(), Some("x-csrf-token"));
        assert_eq!(r.csrf_cookie.as_deref(), Some("SOFI_R_CSRF_TOKEN"));
        assert!(r.csrf_url_decoded);
        assert_eq!(
            recipe_note(&r),
            "captured the /bff/graphql header recipe (3 headers; csrf header `x-csrf-token` \
             from cookie `SOFI_R_CSRF_TOKEN`, url-decoded)"
        );
    }

    #[test]
    fn a_raw_csrf_match_is_not_marked_decoded_and_no_csrf_is_none() {
        let cookies = vec![("SOFI_R_CSRF_TOKEN".to_string(), "plain".to_string())];
        let r = derive_recipe(&[("csrf-token", "plain")], &cookies);
        assert_eq!(r.csrf_cookie.as_deref(), Some("SOFI_R_CSRF_TOKEN"));
        assert!(!r.csrf_url_decoded);

        // No csrf-ish header → no csrf recipe, but names still captured.
        let r = derive_recipe(&[("origin", "https://www.sofi.com")], &cookies);
        assert!(r.csrf_header.is_none());
        assert!(r.csrf_cookie.is_none());
        assert_eq!(r.header_names, vec!["origin".to_string()]);
        assert_eq!(
            recipe_note(&r),
            "captured the /bff/graphql header recipe (1 headers)"
        );
    }

    /// A header name in any case is recorded once, lowercased.
    #[test]
    fn header_names_are_lowercased_and_deduplicated() {
        let r = derive_recipe(&[("Origin", "a"), ("origin", "b"), ("Accept", "c")], &[]);
        assert_eq!(r.header_names, ["accept", "origin"]);
    }

    #[test]
    fn cookie_pairs_splits_the_session_header() {
        let session = Session::from_bundle("SOFI=b; SOFI_R_CSRF_TOKEN=c").unwrap();
        let pairs = cookie_pairs(&session);
        assert!(pairs.contains(&("SOFI".to_string(), "b".to_string())));
        assert!(pairs.contains(&("SOFI_R_CSRF_TOKEN".to_string(), "c".to_string())));
    }

    /// The no-recipe note keeps its wording: what happens without one, and
    /// the command that captures it.
    #[test]
    fn the_no_recipe_note_names_the_fallback_and_the_fix() {
        assert!(NO_RECIPE_NOTE.starts_with("note: no /bff/graphql request seen in the window"));
        assert!(NO_RECIPE_NOTE.contains("modeled header defaults"));
        assert!(NO_RECIPE_NOTE.ends_with("re-run `sfi auth login --browser`"));
    }

    // The tests below run the confirm hook and the recipe step on what a
    // capture hands over, built by hand through pk-cli-browser's `test-util`
    // feature (a dev-dependency), and validate against a loopback server.

    /// A signed-in `sofi.com` jar in the browser's listing order: the Auth0
    /// cookie on the login host, the session cookies on the app host (the
    /// CSRF cookie percent-encoded), and an analytics cookie on the domain.
    fn signed_in_jar() -> Vec<JarCookie> {
        vec![
            JarCookie::for_test("auth0", "dummy-auth0", "login.sofi.com", true, "/"),
            JarCookie::for_test(SESSION_COOKIE, "dummy-bearer", APP_HOST, true, "/"),
            JarCookie::for_test("SOFI_SESSION", "dummy-session", APP_HOST, true, "/"),
            JarCookie::for_test("SOFI_LOGIN", "1", APP_HOST, true, "/"),
            JarCookie::for_test("SOFI_R_CSRF_TOKEN", "dummy%2Fcsrf%3D", APP_HOST, true, "/"),
            JarCookie::for_test("_ga", "dummy-analytics", ".sofi.com", false, "/"),
        ]
    }

    /// The jar before the app redirect: SoFi cookies, but no `SOFI` bearer.
    fn pre_redirect_jar() -> Vec<JarCookie> {
        vec![
            JarCookie::for_test("auth0", "dummy-auth0", "login.sofi.com", true, "/"),
            JarCookie::for_test("SOFI_R_CSRF_TOKEN", "dummy-csrf", APP_HOST, true, "/"),
            JarCookie::for_test("SOFI_LOGIN", "1", APP_HOST, true, "/"),
        ]
    }

    /// The validation read the hook tests pass in: a literal, so neither the
    /// request nor the expected answers depend on `SFI_VALIDATE_PATH`.
    const VALIDATION_PATH: &str = "/dummy/validation-read";

    /// The `Cookie` header of the session [`signed_in_jar`] becomes.
    const SIGNED_IN_COOKIE: &str = "SOFI=dummy-bearer; SOFI_SESSION=dummy-session; SOFI_LOGIN=1; \
                                    SOFI_R_CSRF_TOKEN=dummy%2Fcsrf%3D";

    /// A signed-in capture as `browser_capture` hands it over, without the
    /// app's request.
    fn signed_in() -> Captured {
        Captured::for_test(LABEL, APP_HOST)
            .cookie(SESSION_COOKIE, "dummy-bearer")
            .jar(signed_in_jar())
            .build()
    }

    /// The app's own `/bff/graphql` request: its CSRF header carries the CSRF
    /// cookie URL-decoded.
    fn graphql_request() -> CapturedRequest {
        CapturedRequest::for_test(
            "POST",
            &format!("https://{APP_HOST}{GRAPHQL_PATH}"),
            &[
                ("Apollographql-Client-Name", "dummy-banking-ui"),
                ("Content-Type", "application/json"),
                ("Cookie", SIGNED_IN_COOKIE),
                ("Origin", "https://www.sofi.com"),
                ("X-CSRF-Token", "dummy/csrf="),
            ],
        )
    }

    /// A one-shot loopback server standing in for SoFi: it answers the first
    /// request with `status`, `content_type` and `body`. Returns its base URL
    /// and a handle that yields the request head it read, or `None` when no
    /// request came within 10 s, so a hook that never reads fails its test
    /// instead of hanging it.
    fn loopback(
        status: &str,
        content_type: &str,
        body: &str,
    ) -> (String, JoinHandle<Option<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("non-blocking accept");
        let base = format!(
            "http://{}",
            listener.local_addr().expect("loopback address")
        );
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return None,
                }
            };
            stream.set_nonblocking(false).ok()?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .ok()?;
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            stream.write_all(response.as_bytes()).ok()?;
            Some(String::from_utf8_lossy(&head).into_owned())
        });
        (base, handle)
    }

    /// A header's value in a request head, by case-insensitive name.
    fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines().skip(1).find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    /// Run the confirm hook on `candidate`, reading [`VALIDATION_PATH`] with a
    /// client on a loopback server answering `status`, and return its answer
    /// and the request it made.
    fn confirm_on_loopback(
        candidate: &Captured,
        status: &str,
        content_type: &str,
        body: &str,
    ) -> (Confirm, String) {
        let (base, server) = loopback(status, content_type, body);
        let answer = confirm_with(
            candidate,
            &Window::default(),
            false,
            VALIDATION_PATH,
            || Sofi::with_base(&base),
        );
        let head = server
            .join()
            .expect("the loopback server ran")
            .unwrap_or_else(|| panic!("{status}: the hook made no validation read"));
        (answer, head)
    }

    /// Without the `SOFI` cookie the hook keeps the wait going and builds no
    /// client, so nothing is read: a capture without a jar, and a jar holding
    /// only the cookies set before the app redirect. `confirm` itself is run
    /// too, since this branch makes no request.
    #[test]
    fn a_capture_without_the_bearer_keeps_waiting_without_a_read() {
        for candidate in [
            Captured::for_test(LABEL, APP_HOST).build(),
            Captured::for_test(LABEL, APP_HOST)
                .jar(pre_redirect_jar())
                .build(),
        ] {
            let answers = [
                confirm(&candidate, false, &Window::default()),
                confirm_with(
                    &candidate,
                    &Window::default(),
                    false,
                    VALIDATION_PATH,
                    || panic!("no client is built before the SOFI cookie is set"),
                ),
            ];
            for answer in answers {
                match answer {
                    Confirm::NotYet(reason) => {
                        assert_eq!(reason, "the sofi.com jar holds no SOFI cookie yet")
                    }
                    other => panic!("expected NotYet, got {other:?}"),
                }
            }
        }
    }

    /// A signed-in capture is validated with one GET of the path given,
    /// replaying the session's cookies, and a JSON answer captures it.
    #[test]
    fn a_signed_in_capture_is_ready_when_the_validation_read_works() {
        let accounts = include_str!("../tests/fixtures/accounts.json");
        let (answer, head) =
            confirm_on_loopback(&signed_in(), "200 OK", "application/json", accounts);
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert!(
            head.starts_with(&format!("GET {VALIDATION_PATH} HTTP/1.1\r\n")),
            "{head}"
        );
        assert_eq!(header(&head, "cookie"), Some(SIGNED_IN_COOKIE));
    }

    /// A refused read keeps the tab open, with a reason that names the read and what
    /// it was told: a 401, a plain 403, an HTML login page behind a 200 and a login
    /// page holding a challenge's words outside its title. So does another status the
    /// provider chose, in both profiles.
    #[test]
    fn a_signed_in_capture_keeps_waiting_while_the_read_is_refused() {
        let login_page = include_str!("../tests/fixtures/login-page-with-challenge-words.html");
        for kept_profile in [false, true] {
            for (status, content_type, body, told) in [
                ("401 Unauthorized", "application/json", "", "HTTP 401"),
                ("403 Forbidden", "application/json", "", "bot check"),
                (
                    "200 OK",
                    "text/html",
                    "<!DOCTYPE html><html>Sign in</html>",
                    "probably lapsed",
                ),
                ("200 OK", "text/html", login_page, "probably lapsed"),
                ("400 Bad Request", "application/json", "", "HTTP 400"),
            ] {
                let (answer, note) = read_once(kept_profile, status, content_type, body);
                match answer {
                    Confirm::NotYet(reason) => {
                        let start = format!("the validation read {VALIDATION_PATH} ");
                        assert!(reason.starts_with(&start), "{reason}");
                        assert!(reason.contains(told), "{status}: {reason}");
                    }
                    other => panic!("{status} {content_type}: expected NotYet, got {other:?}"),
                }
                assert_eq!(note, None, "{status}");
            }
        }
    }

    /// One poll's read through the hook's decision.
    fn read_once(
        kept_profile: bool,
        status: &str,
        content_type: &str,
        body: &str,
    ) -> (Confirm, Option<Unverified>) {
        let (base, server) = loopback(status, content_type, body);
        let answer = decide(&signed_in(), kept_profile, VALIDATION_PATH, || {
            Sofi::with_base(&base)
        });
        server.join().expect("the loopback server ran");
        answer
    }

    /// What can't decide, as (status, content type, body, what the reason says, whether
    /// an edge block said it).
    const CANT_DECIDE: [(&str, &str, &str, &str, bool); 10] = [
        (
            "429 Too Many Requests",
            "application/json",
            "",
            "HTTP 429",
            false,
        ),
        (
            "500 Internal Server Error",
            "application/json",
            "",
            "HTTP 500",
            false,
        ),
        (
            "503 Service Unavailable",
            "application/json",
            "",
            "HTTP 503",
            false,
        ),
        (
            "502 Bad Gateway",
            "text/html",
            "<html></html>",
            "HTTP 502",
            false,
        ),
        (
            "403 Forbidden",
            "text/html",
            "<html>dummy-body</html>",
            "bot check",
            true,
        ),
        (
            "429 Too Many Requests",
            "text/html",
            "<html>dummy-body</html>",
            "bot check",
            true,
        ),
        (
            "503 Service Unavailable",
            "text/html",
            "<html><title>Just a moment...</title>dummy-body</html>",
            "bot check",
            true,
        ),
        (
            "200 OK",
            "text/html",
            "<!DOCTYPE html><html><title>Just a moment...</title>dummy-body</html>",
            "bot check",
            true,
        ),
        ("200 OK", "application/json", "", "nothing in it", false),
        (
            "200 OK",
            "application/json",
            "dummy-not-json",
            "no JSON",
            false,
        ),
    ];

    /// In a kept profile the `SOFI` cookie may be left from an earlier sign-in and does
    /// not survive the stop, so what can't decide is `Undecided`: the crate keeps the
    /// tab and the jar, and nothing is accepted. The reason holds fixed parts, never
    /// the answer's body or a cookie value.
    #[test]
    fn a_kept_profile_is_undecided_on_what_cannot_decide() {
        for (status, content_type, body, said, _) in CANT_DECIDE {
            let (answer, note) = read_once(true, status, content_type, body);
            let Confirm::Undecided {
                reason,
                retry_after,
                ..
            } = answer
            else {
                panic!("{status} {body:?}: expected Undecided, got {answer:?}");
            };
            assert!(reason.contains(said), "{status} {body:?}: {reason}");
            assert!(!reason.contains("dummy-"), "{status} {body:?}: {reason}");
            assert_eq!(retry_after, None, "{status} {body:?}");
            assert_eq!(note, None, "{status} {body:?}: nothing is accepted");
        }
    }

    /// A scratch profile started empty, so the cookie is this sign-in's: what can't
    /// decide stores it unverified, and says whether an edge block was the cause.
    #[test]
    fn a_scratch_profile_stores_unverified_on_what_cannot_decide() {
        for (status, content_type, body, said, edge_block) in CANT_DECIDE {
            let (answer, note) = read_once(false, status, content_type, body);
            assert!(
                matches!(answer, Confirm::Ready),
                "{status} {body:?}: {answer:?}"
            );
            let note = note.expect("the reason is recorded");
            assert!(note.why.contains(said), "{status} {body:?}: {note:?}");
            assert!(!note.why.contains("dummy-"), "{status} {body:?}: {note:?}");
            assert_eq!(note.edge_block, edge_block, "{status} {body:?}");
        }
    }

    /// A 2xx alone is not acceptance: on the accounts read a parseable answer with no
    /// account keeps the wait going in both profiles.
    #[test]
    fn a_two_hundred_with_no_account_keeps_waiting() {
        for kept_profile in [false, true] {
            for body in ["{}", "[]", "true", "0", r#""dummy""#, r#"{"accounts":[]}"#] {
                let (base, server) = loopback("200 OK", "application/json", body);
                let (answer, note) = decide(&signed_in(), kept_profile, ACCOUNTS_PATH, || {
                    Sofi::with_base(&base)
                });
                server.join().expect("the loopback server ran");
                assert!(
                    matches!(&answer, Confirm::NotYet(reason) if reason.contains("no account")),
                    "{body}: {answer:?}"
                );
                assert_eq!(note, None, "{body}");
            }
        }
    }

    /// The provider's `Retry-After` reaches the crate, from a throttle and from an edge
    /// block's page.
    #[test]
    fn undecided_passes_the_providers_retry_after() {
        for (status, content_type) in [
            ("429 Too Many Requests", "application/json"),
            ("403 Forbidden", "text/html"),
        ] {
            let with_header = format!("{content_type}\r\nRetry-After: 120");
            let (answer, _) = read_once(true, status, &with_header, "<html></html>");
            match answer {
                Confirm::Undecided { retry_after, .. } => {
                    assert_eq!(retry_after, Some(Duration::from_secs(120)), "{status}");
                }
                other => panic!("{status}: expected Undecided, got {other:?}"),
            }
        }
    }

    /// A reason names the status, not the provider's message: this one reaches stderr.
    #[test]
    fn an_undecided_reason_omits_the_providers_message() {
        let body = r#"{"message":"dummy detail"}"#;
        let (answer, _) = read_once(true, "500 Internal Server Error", "application/json", body);
        match answer {
            Confirm::Undecided { reason, .. } => {
                assert!(reason.contains("HTTP 500"), "{reason}");
                assert!(!reason.contains("dummy detail"), "{reason}");
            }
            other => panic!("expected Undecided, got {other:?}"),
        }
    }

    /// A request with no answer at all is undecided too, and its reason is fixed.
    #[test]
    fn a_kept_profile_is_undecided_on_a_transport_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let (answer, note) = decide(&signed_in(), true, VALIDATION_PATH, || {
            Sofi::with_base(&base)
        });
        match answer {
            Confirm::Undecided { reason, .. } => assert_eq!(
                reason,
                format!("the validation read {VALIDATION_PATH} got no answer")
            ),
            other => panic!("expected Undecided, got {other:?}"),
        }
        assert_eq!(note, None);
    }

    /// A 404 in a kept profile ends the wait: no later poll can change it.
    #[test]
    fn a_kept_profile_ends_the_wait_on_a_missing_path() {
        let (answer, note) = read_once(true, "404 Not Found", "application/json", "");
        match answer {
            Confirm::Fail(e) => {
                let text = e.to_string();
                assert_eq!(e.exit_code(), 5, "{text}");
                assert!(text.contains("404"), "{text}");
                assert!(text.contains("nothing further to enter"), "{text}");
                assert!(text.contains("--fresh-profile"), "{text}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        assert_eq!(note, None);
    }

    /// A wait that runs out undecided is exit 5, and keeps the kept profile's note.
    #[test]
    fn a_wait_that_runs_out_undecided_is_exit_5() {
        let err = noting_kept_profile::<()>(Some("dummy note".into()), || {
            Err(BrowserError::Undecided("dummy reason".into()))
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("dummy note"), "{err}");
    }

    /// The window hands the reason to the store, once.
    #[test]
    fn a_scratch_profile_records_why_it_accepted_unverified() {
        let window = Window::default();
        let (base, server) = loopback("503 Service Unavailable", "application/json", "");
        let answer = confirm_with(&signed_in(), &window, false, VALIDATION_PATH, || {
            Sofi::with_base(&base)
        });
        server.join().expect("the loopback server ran");
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        let why = window.unverified().expect("the reason is recorded");
        assert!(why.why.contains("HTTP 503"), "{why:?}");
        assert_eq!(window.unverified(), None, "it is handed over once");
    }

    /// The stored session's state decides whether an unverified one may replace it.
    /// A plain 403 could be a bot check, so it can't tell.
    #[test]
    fn a_stored_session_is_read_once_to_learn_its_state() {
        let stored = dummy_stored_session();
        let state = |status: &str, content_type: &str, body: &str| {
            let (base, server) = loopback(status, content_type, body);
            let state = stored_state_with(Some(&stored), ACCOUNTS_PATH, || Sofi::with_base(&base));
            server.join().expect("the loopback server ran");
            state
        };
        let working = include_str!("../tests/fixtures/accounts.json");
        let json = "application/json";
        for (status, content_type, body, expected) in [
            ("200 OK", json, working, StoredSession::Working),
            ("401 Unauthorized", json, "", StoredSession::Dead),
            (
                "200 OK",
                "text/html",
                "<html>Sign in</html>",
                StoredSession::Dead,
            ),
            ("200 OK", json, "{}", StoredSession::Dead),
            ("403 Forbidden", json, "", StoredSession::CantTell),
            (
                "403 Forbidden",
                "text/html",
                "<html></html>",
                StoredSession::CantTell,
            ),
            ("503 Service Unavailable", json, "", StoredSession::CantTell),
            ("429 Too Many Requests", json, "", StoredSession::CantTell),
            ("200 OK", json, "", StoredSession::CantTell),
            ("404 Not Found", json, "", StoredSession::CantTell),
        ] {
            assert_eq!(state(status, content_type, body), expected, "{status}");
        }

        let no_read = || -> Result<Sofi, CliError> { panic!("nothing to read") };
        assert_eq!(
            stored_state_with(None, "/x", no_read),
            StoredSession::Absent
        );
        assert_eq!(
            stored_state_with(Some("not json"), "/x", no_read),
            StoredSession::Dead
        );
    }

    fn dummy_stored_session() -> String {
        Session {
            cookie: "SOFI=dummy-stored".into(),
            csrf_token: None,
            expires_at: None,
            graphql_recipe: None,
        }
        .to_secret()
        .expose()
        .to_string()
    }

    fn unverified(edge_block: bool) -> Unverified {
        Unverified {
            why: "dummy why".into(),
            edge_block,
        }
    }

    /// An unverified session never replaces one that works (exit 2) or that could not
    /// be checked (exit 5). Each refusal says nothing was stored and names the way out.
    #[test]
    fn an_unverified_session_does_not_replace_a_working_one() {
        assert!(refuse_replacing(&StoredSession::Absent, &unverified(false)).is_ok());
        assert!(refuse_replacing(&StoredSession::Dead, &unverified(false)).is_ok());
        for (stored, exit, said) in [
            (StoredSession::Working, 2, "still works"),
            (StoredSession::CantTell, 5, "could not be checked"),
        ] {
            let err = refuse_replacing(&stored, &unverified(false)).unwrap_err();
            assert_eq!(err.exit_code(), exit);
            let text = err.to_string();
            assert!(text.contains(said), "{text}");
            assert!(text.contains("dummy why"), "{text}");
            assert!(text.contains("nothing was stored"), "{text}");
            assert!(
                text.contains("sfi auth login --browser --overwrite"),
                "{text}"
            );
            assert!(!text.contains("another network"), "{text}");
        }
    }

    /// An edge block's message says a new sign-in may not clear it before it names the
    /// way out. A 429, a 5xx or a dropped connection keeps its wording.
    #[test]
    fn an_edge_block_says_a_new_sign_in_may_not_clear_it_first() {
        let advice_before_the_way_out = |text: &str| {
            let advice = text.find("A new sign-in may not clear this").expect(text);
            assert!(
                text.contains("the block is on the client rather than the session"),
                "{text}"
            );
            assert!(text.contains("Wait or try another network"), "{text}");
            let way_out = text
                .find("sfi auth login --browser --overwrite")
                .expect(text);
            assert!(advice < way_out, "{text}");
        };
        advice_before_the_way_out(&unverified_warning(&unverified(true)));
        for stored in [StoredSession::Working, StoredSession::CantTell] {
            let err = refuse_replacing(&stored, &unverified(true)).unwrap_err();
            advice_before_the_way_out(&err.to_string());
        }
    }

    #[test]
    fn the_unverified_warning_names_the_cause_and_the_way_out() {
        let line = unverified_warning(&unverified(false));
        assert!(line.starts_with("warning: "), "{line}");
        assert!(line.contains("stored unverified"), "{line}");
        assert!(line.contains("dummy why"), "{line}");
        assert!(
            line.contains("sfi auth login --browser --overwrite"),
            "{line}"
        );
        assert!(!line.contains("another network"), "{line}");
    }

    /// Every failure once Chrome may have used a kept profile carries the note
    /// and keeps its exit code, the ones most likely to leave a live session
    /// included.
    #[test]
    fn every_failed_sign_in_says_the_kept_profile_stays() {
        let note = kept_profile_note(false);
        let cases: Vec<(BrowserError, i32, &str)> = vec![
            (BrowserError::TimedOut("timed out.".into()), 3, "timed out"),
            (
                BrowserError::WindowClosed("window closed.".into()),
                3,
                "window closed",
            ),
            (BrowserError::Canceled, 1, "browser login canceled"),
            (
                BrowserError::Launch("dummy launch".into()),
                1,
                "dummy launch",
            ),
            (
                BrowserError::Handler(CliError::Upstream("HTTP 429".into())),
                5,
                "HTTP 429",
            ),
            (
                BrowserError::Handler(CliError::Keychain("dummy write".into())),
                1,
                "dummy write",
            ),
        ];
        for (err, code, message) in cases {
            let noted = noting_kept_profile::<()>(note.clone(), || Err(err)).unwrap_err();
            assert_eq!(noted.exit_code(), code, "{message}");
            let text = noted.to_string();
            assert!(text.contains(message), "{text}");
            assert!(
                text.contains(
                    "The kept browser profile stays on disk; `sfi auth logout` removes it, \
                     and clears the stored session too."
                ),
                "{text}"
            );
        }
        assert_eq!(noting_kept_profile(note, || Ok(7)).unwrap(), 7);
    }

    /// A refusal before Chrome uses the profile leaves nothing new, so it says
    /// nothing about the profile: the note would be false or point at a logout
    /// that refuses too.
    #[test]
    fn a_refusal_before_chrome_uses_the_profile_carries_no_note() {
        let refusals = [
            BrowserError::Invalid("dummy invalid".into()),
            BrowserError::ChromeNotFound("dummy no chrome".into()),
            BrowserError::Profile("dummy repair".into()),
            BrowserError::ProfileInUse("dummy in use".into()),
        ];
        for err in refusals {
            let plain = err.to_string();
            let refused =
                noting_kept_profile::<()>(kept_profile_note(false), || Err(err)).unwrap_err();
            assert_eq!(refused.exit_code(), 1, "{plain}");
            assert_eq!(refused.to_string(), plain);
        }
    }

    /// A scratch profile is gone by then, so `--fresh-profile` adds nothing.
    #[test]
    fn a_fresh_profile_sign_in_carries_no_note() {
        assert_eq!(kept_profile_note(true), None);
        let err = noting_kept_profile::<()>(kept_profile_note(true), || {
            Err(BrowserError::TimedOut("timed out.".into()))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "timed out.");
    }

    /// A service override is a test namespace: the sign-in takes a scratch
    /// profile, as `--fresh-profile` does, and says so once. No browser runs here.
    #[test]
    fn a_service_override_makes_the_sign_in_use_a_scratch_profile() {
        let line =
            "SFI_KEYCHAIN_SERVICE is set, so this sign-in uses a scratch browser profile, as with \
                    --fresh-profile";
        assert_eq!(scratch_profile_choice(false, false), (false, None));
        assert_eq!(scratch_profile_choice(true, false), (true, None));
        assert_eq!(
            scratch_profile_choice(false, true),
            (true, Some(line.to_string()))
        );
        // The owner asked for it already, so there is nothing to explain.
        assert_eq!(scratch_profile_choice(true, true), (true, None));
        // The note follows the choice, so a failure under an override has none.
        let (fresh_profile, _) = scratch_profile_choice(false, true);
        assert_eq!(kept_profile_note(fresh_profile), None);
    }

    /// A client that cannot be built ends the wait with its own error rather
    /// than holding the tab open: the hook's only `Fail`.
    #[test]
    fn a_client_that_cannot_be_built_ends_the_wait() {
        let answer = confirm_with(
            &signed_in(),
            &Window::default(),
            false,
            VALIDATION_PATH,
            || Err(CliError::Other("dummy: no HTTP client".into())),
        );
        match answer {
            Confirm::Fail(e) => {
                assert_eq!(e.exit_code(), 1);
                assert_eq!(e.to_string(), "dummy: no HTTP client");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// The recipe step on a capture holding the app's request: the session
    /// is the jar's four session cookies in listing order, and the recipe the
    /// request's header names (the client-managed ones dropped) and the
    /// cookie its CSRF header echoes, URL-decoded. No value is stored.
    #[test]
    fn a_capture_with_the_apps_request_becomes_the_session_and_its_recipe() {
        let captured = Captured::for_test(LABEL, APP_HOST)
            .cookie(SESSION_COOKIE, "dummy-bearer")
            .jar(signed_in_jar())
            .request(graphql_request())
            .build();
        let session = session_from_capture(&captured).expect("SOFI is in the jar");
        assert_eq!(session.cookie, SIGNED_IN_COOKIE);
        assert_eq!(session.csrf_token.as_deref(), Some("dummy%2Fcsrf%3D"));
        let recipe = session.graphql_recipe.expect("the app's request was seen");
        assert_eq!(
            recipe,
            GraphqlRecipe {
                header_names: vec![
                    "apollographql-client-name".into(),
                    "origin".into(),
                    "x-csrf-token".into(),
                ],
                csrf_header: Some("x-csrf-token".into()),
                csrf_cookie: Some("SOFI_R_CSRF_TOKEN".into()),
                csrf_url_decoded: true,
            }
        );
        let stored = serde_json::to_string(&recipe).unwrap();
        for value in [
            "dummy-banking-ui",
            "dummy/csrf=",
            "dummy%2Fcsrf%3D",
            "dummy-bearer",
        ] {
            assert!(!stored.contains(value), "{value} stored: {stored}");
        }
        assert_eq!(
            recipe_note(&recipe),
            "captured the /bff/graphql header recipe (3 headers; csrf header `x-csrf-token` \
             from cookie `SOFI_R_CSRF_TOKEN`, url-decoded)"
        );
    }

    /// Without the app's request the session is captured without a recipe,
    /// and the client falls back to its modeled headers.
    #[test]
    fn a_capture_without_the_apps_request_has_no_recipe() {
        let session = session_from_capture(&signed_in()).expect("SOFI is in the jar");
        assert_eq!(session.cookie, SIGNED_IN_COOKIE);
        assert!(session.graphql_recipe.is_none());
    }

    /// A capture whose jar lost the `SOFI` cookie is no session, request or
    /// not.
    #[test]
    fn a_capture_without_the_bearer_yields_no_session() {
        let captured = Captured::for_test(LABEL, APP_HOST)
            .jar(pre_redirect_jar())
            .request(graphql_request())
            .build();
        let err = session_from_capture(&captured).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            err.to_string(),
            "the browser capture came back without the SOFI cookie"
        );
    }
}
