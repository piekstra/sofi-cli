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
//! directory's `0700` mode protects. It also means a `SOFI` cookie can be left
//! from an earlier sign-in, so in a kept profile only a working validation read
//! proves the owner is in ([`confirm_outcome`]).
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

use std::time::Duration;

use pk_cli_browser::{BrowserError, Capture, Captured, Confirm, HostRule, Launch, DEFAULT_TIMEOUT};
use pk_cli_core::CliError;

use crate::client::{
    percent_decode, validation_path, GraphqlRecipe, Session, Sofi, GRAPHQL_PATH, LOGIN_PAGE_URL,
    SESSION_COOKIE,
};
use crate::config;

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
/// the recipe, and [`confirm`] before the tab closes. `quiet` suppresses the
/// validation note the confirm hook may print.
fn browser_capture(kept_profile: bool, quiet: bool) -> Result<Capture, CliError> {
    Ok(Capture::new(LABEL, HostRule::exact(APP_HOST)?)
        .cookie(format!("https://{APP_HOST}/"), SESSION_COOKIE)
        .cookie_jar(JAR_DOMAIN)
        .optional_request(
            format!("https://{APP_HOST}{GRAPHQL_PATH}"),
            RECIPE_OBSERVE_DEADLINE,
        )
        .hint(SIGN_IN_HINT)
        .confirm(move |candidate| confirm(candidate, kept_profile, quiet)))
}

/// Open the browser, wait for the owner to finish logging in, and return a
/// validated [`Session`], with the app's GraphQL header recipe when a request
/// was seen. `fresh_profile` runs this sign-in in a scratch profile instead of
/// the one sfi keeps. `quiet` suppresses the progress lines on stderr.
pub fn capture_session(fresh_profile: bool, quiet: bool) -> Result<Session, CliError> {
    // The crate keeps a profile on unix only; elsewhere every sign-in is scratch.
    let kept_profile = !fresh_profile && cfg!(unix);
    let captured = pk_cli_browser::capture(
        Launch::new(config::BIN)
            .url(LOGIN_PAGE_URL)
            .fresh_profile(fresh_profile)
            .quiet(quiet),
        &browser_capture(kept_profile, quiet)?,
        DEFAULT_TIMEOUT,
    )
    .map_err(|e| note_kept_profile(e, kept_profile))?;
    let session = session_from_capture(&captured)?;
    if !quiet {
        match &session.graphql_recipe {
            Some(recipe) => eprintln!("{}", recipe_note(recipe)),
            None => eprintln!("{NO_RECIPE_NOTE}"),
        }
    }
    Ok(session)
}

/// A sign-in that timed out or lost its window still leaves the kept profile on
/// disk, with whatever that attempt put there, so its error says so and names
/// the way to remove it. The exit code stays the crate's.
fn note_kept_profile(err: BrowserError, kept_profile: bool) -> BrowserError {
    let note = |message: String| {
        format!(
            "{message} The kept browser profile stays on disk; `{} auth logout` removes it, and \
             clears the stored session too.",
            config::BIN
        )
    };
    match err {
        BrowserError::TimedOut(m) if kept_profile => BrowserError::TimedOut(note(m)),
        BrowserError::WindowClosed(m) if kept_profile => BrowserError::WindowClosed(note(m)),
        other => other,
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
fn confirm(candidate: &Captured, kept_profile: bool, quiet: bool) -> Confirm {
    confirm_with(
        candidate,
        quiet,
        kept_profile,
        &validation_path(),
        Sofi::new,
    )
}

/// The confirm hook with the validation read's path and the client it goes
/// through, both given, so nothing here reads the environment: a jar without
/// the `SOFI` cookie keeps the wait going without building a client;
/// otherwise one read of `path` decides ([`confirm_outcome`]). A test passes
/// a literal path and a client on a loopback server.
fn confirm_with(
    candidate: &Captured,
    quiet: bool,
    kept_profile: bool,
    path: &str,
    client: impl FnOnce() -> Result<Sofi, CliError>,
) -> Confirm {
    let Some(session) = session_from_jar(candidate) else {
        return Confirm::NotYet(format!(
            "the {JAR_DOMAIN} jar holds no {SESSION_COOKIE} cookie yet"
        ));
    };
    let (answer, note) = confirm_outcome(validate(client, &session, path), path, kept_profile);
    if let (Some(note), false) = (note, quiet) {
        eprintln!("note: {note}");
    }
    answer
}

/// What a validation read means for the capture, and the note to print with
/// it. Pure, so the mapping is tested without a browser or a live endpoint:
///
/// - the read worked: capture the session;
/// - the read answered as signed out: keep the tab open and ask again next
///   poll (the reason is named if the wait times out);
/// - the read was inconclusive, in a scratch profile: capture the session on the
///   `SOFI` cookie, and say so. That profile started empty, so the cookie came
///   from this sign-in;
/// - the read was inconclusive, in a kept profile: keep the tab open and ask
///   again next poll. The cookie may be left from an earlier sign-in, so without
///   a working read it proves nothing;
/// - the client could not be built: end the wait with that error.
fn confirm_outcome(
    validated: Result<Probe, CliError>,
    path: &str,
    kept_profile: bool,
) -> (Confirm, Option<String>) {
    match validated {
        Ok(Probe::Ready) => (Confirm::Ready, None),
        Ok(Probe::NotYet) => (
            Confirm::NotYet(format!("the validation read {path} answered as signed out")),
            None,
        ),
        Ok(Probe::Unverifiable(why)) if kept_profile => (
            Confirm::NotYet(format!(
                "{why}; the kept browser profile's {SESSION_COOKIE} cookie may be from an \
                 earlier sign-in, so it was not accepted without that read (--fresh-profile \
                 accepts it)"
            )),
            None,
        ),
        Ok(Probe::Unverifiable(why)) => (
            Confirm::Ready,
            Some(format!("{why}; accepting on the {SESSION_COOKIE} cookie")),
        ),
        Err(e) => (Confirm::Fail(e), None),
    }
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
    /// The session works — a real JSON read came back.
    Ready,
    /// Not signed in yet (HTML login page / redirect / 401) — keep waiting.
    NotYet,
    /// Can't tell (the validation endpoint is itself unverified — a 404, or a
    /// transient upstream error). Accept on the bearer cookie, but say so.
    Unverifiable(String),
}

/// Classify a validation read. Pure, so the accept/keep-waiting/accept-unverified
/// decision is tested without a live endpoint.
///
/// The validation endpoint (`validation_path`) is swappable because it was
/// UNVERIFIED-LIVE when this was written, so a 404 must not block a capture
/// whose bearer cookie is present.
fn probe_outcome(res: &Result<serde_json::Value, CliError>, path: &str) -> Probe {
    match res {
        Ok(_) => Probe::Ready,
        // HTML-where-JSON-expected, a login redirect, or a 401/403 all map to
        // Auth: the owner hasn't finished signing in.
        Err(CliError::Auth(_)) => Probe::NotYet,
        Err(CliError::NotFound(_)) => Probe::Unverifiable(format!(
            "the validation read {path} returned 404 — that endpoint is unverified \
             (set SFI_VALIDATE_PATH to a known read)"
        )),
        Err(e) => Probe::Unverifiable(format!("the validation read {path} was inconclusive ({e})")),
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
    let res = sofi.get(session, &sofi.url(path), &[]);
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
        for quiet in [false, true] {
            let capture = browser_capture(false, quiet).unwrap();
            capture.validate().unwrap();
            assert_eq!(capture.label(), "SoFi");
        }
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

    #[test]
    fn probe_ready_when_a_read_succeeds() {
        assert_eq!(
            probe_outcome(&Ok(json!({"accounts": []})), "/x"),
            Probe::Ready
        );
    }

    #[test]
    fn probe_not_yet_on_an_auth_answer() {
        // HTML/login-redirect/401 all surface as CliError::Auth.
        assert_eq!(
            probe_outcome(&Err(CliError::Auth("html login page".into())), "/x"),
            Probe::NotYet
        );
    }

    #[test]
    fn probe_unverifiable_on_a_404_or_other_error() {
        // The default validation endpoint is swappable, so a 404 must not
        // block a capture whose bearer cookie is present.
        match probe_outcome(&Err(CliError::NotFound("404".into())), "/accounts") {
            Probe::Unverifiable(why) => {
                assert!(why.contains("/accounts"));
                assert!(why.contains("SFI_VALIDATE_PATH"));
            }
            other => panic!("expected Unverifiable, got {other:?}"),
        }
        assert!(matches!(
            probe_outcome(&Err(CliError::Upstream("500".into())), "/x"),
            Probe::Unverifiable(_)
        ));
    }

    /// The confirm hook's mapping: a working read captures, a signed-out
    /// answer keeps the tab open with a reason naming the read, an
    /// inconclusive read captures with a note, and a client that cannot be
    /// built ends the wait with its own error.
    #[test]
    fn the_confirm_mapping_follows_the_probe() {
        let path = "/money/api/public/v2/accounts";

        let (answer, note) = confirm_outcome(Ok(Probe::Ready), path, false);
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert_eq!(note, None);

        let (answer, note) = confirm_outcome(Ok(Probe::NotYet), path, false);
        match answer {
            Confirm::NotYet(reason) => {
                assert_eq!(
                    reason,
                    format!("the validation read {path} answered as signed out")
                )
            }
            other => panic!("expected NotYet, got {other:?}"),
        }
        assert_eq!(note, None);

        let (answer, note) = confirm_outcome(Ok(Probe::Unverifiable("why".into())), path, false);
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert_eq!(note.as_deref(), Some("why; accepting on the SOFI cookie"));

        let (answer, note) = confirm_outcome(Err(CliError::Other("no client".into())), path, false);
        match answer {
            Confirm::Fail(e) => {
                assert_eq!(e.exit_code(), 1);
                assert_eq!(e.to_string(), "no client");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        assert_eq!(note, None);
    }

    /// From an HTTP answer to the hook's answer, end to end: a 401 keeps
    /// waiting, a 404 captures with the SFI_VALIDATE_PATH note, a read
    /// captures silently.
    #[test]
    fn a_validation_answer_maps_to_the_confirm_answer() {
        let path = "/x";
        let confirm_for = |res: Result<serde_json::Value, CliError>| {
            confirm_outcome(Ok(probe_outcome(&res, path)), path, false)
        };
        let (answer, _) = confirm_for(Err(CliError::Auth("401".into())));
        assert!(matches!(answer, Confirm::NotYet(_)), "{answer:?}");
        let (answer, note) = confirm_for(Err(CliError::NotFound("404".into())));
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert!(note.unwrap().contains("SFI_VALIDATE_PATH"));
        let (answer, note) = confirm_for(Ok(json!({})));
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert_eq!(note, None);
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
        let answer = confirm_with(candidate, true, false, VALIDATION_PATH, || {
            Sofi::with_base(&base)
        });
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
            for quiet in [false, true] {
                let answers = [
                    confirm(&candidate, false, quiet),
                    confirm_with(&candidate, quiet, false, VALIDATION_PATH, || {
                        panic!("no client is built before the SOFI cookie is set")
                    }),
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

    /// A read that answers as signed out keeps the tab open, with a reason
    /// naming the read: a 401, a 403, and an HTML login page behind a 200.
    #[test]
    fn a_signed_in_capture_keeps_waiting_while_the_read_answers_signed_out() {
        let want = format!("the validation read {VALIDATION_PATH} answered as signed out");
        for (status, content_type, body) in [
            ("401 Unauthorized", "application/json", ""),
            ("403 Forbidden", "application/json", ""),
            ("200 OK", "text/html", "<!DOCTYPE html><html>Sign in</html>"),
        ] {
            let (answer, head) = confirm_on_loopback(&signed_in(), status, content_type, body);
            match answer {
                Confirm::NotYet(reason) => assert_eq!(reason, want, "{status} {content_type}"),
                other => panic!("{status} {content_type}: expected NotYet, got {other:?}"),
            }
            assert_eq!(header(&head, "cookie"), Some(SIGNED_IN_COOKIE));
        }
    }

    /// A read that says nothing about the session (a 404 from the unverified
    /// validation endpoint, or a 5xx) captures on the `SOFI` cookie.
    #[test]
    fn a_signed_in_capture_is_ready_on_an_inconclusive_read() {
        for status in ["404 Not Found", "500 Internal Server Error"] {
            let (answer, _) = confirm_on_loopback(&signed_in(), status, "application/json", "");
            assert!(matches!(answer, Confirm::Ready), "{status}: {answer:?}");
        }
    }

    /// In a kept profile a `SOFI` cookie may be left from an earlier sign-in, so
    /// an inconclusive read keeps the wait going instead of storing it, and the
    /// reason, shown if the wait times out, names the way past it. A working
    /// read and a signed-out answer mean what they mean in a scratch profile.
    #[test]
    fn a_kept_profiles_cookie_is_not_accepted_without_a_working_read() {
        let path = "/x";
        let kept = |res: Result<serde_json::Value, CliError>| {
            confirm_outcome(Ok(probe_outcome(&res, path)), path, true)
        };
        for res in [
            Err(CliError::NotFound("404".into())),
            Err(CliError::Upstream("500".into())),
        ] {
            let (answer, note) = kept(res);
            match answer {
                Confirm::NotYet(reason) => {
                    assert!(reason.contains("the validation read /x"), "{reason}");
                    assert!(reason.contains("--fresh-profile"), "{reason}");
                    assert!(!reason.contains("accepting"), "{reason}");
                }
                other => panic!("expected NotYet, got {other:?}"),
            }
            assert_eq!(note, None);
        }
        let (answer, _) = kept(Ok(json!({})));
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        let (answer, _) = kept(Err(CliError::Auth("401".into())));
        assert!(matches!(answer, Confirm::NotYet(_)), "{answer:?}");
    }

    /// A failed sign-in in a kept profile says the profile stays and how to
    /// remove it, keeping the crate's message and exit code. A scratch profile
    /// is gone by then, so it says nothing, and other errors pass unchanged.
    #[test]
    fn a_failed_sign_in_says_the_kept_profile_stays() {
        let failures = [
            BrowserError::TimedOut("timed out.".into()),
            BrowserError::WindowClosed("window closed.".into()),
        ];
        for err in failures {
            let plain = err.to_string();
            let noted = note_kept_profile(err, true);
            assert_eq!(noted.exit_code(), 3);
            assert_eq!(
                noted.to_string(),
                format!(
                    "{plain} The kept browser profile stays on disk; `sfi auth logout` removes \
                     it, and clears the stored session too."
                )
            );
        }
        let scratch = note_kept_profile(BrowserError::TimedOut("timed out.".into()), false);
        assert_eq!(scratch.to_string(), "timed out.");
        let canceled = note_kept_profile(BrowserError::Canceled, true);
        assert_eq!(canceled.to_string(), "browser login canceled");
    }

    /// A client that cannot be built ends the wait with its own error rather
    /// than holding the tab open: the hook's only `Fail`.
    #[test]
    fn a_client_that_cannot_be_built_ends_the_wait() {
        let answer = confirm_with(&signed_in(), true, false, VALIDATION_PATH, || {
            Err(CliError::Other("dummy: no HTTP client".into()))
        });
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
