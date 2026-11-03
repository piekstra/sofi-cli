//! HTTP against SoFi's private (member) API, the MFA login dance, the GraphQL
//! transactions read, and verified statement downloads.
//!
//! SoFi publishes no public member API. Every constant and path here comes
//! from thin community reverse-engineering (two browser-extension projects —
//! see `docs/api.md` for citations) and **has not been confirmed against the
//! live service by this project**. The read endpoints are transcribed from
//! working community code; the *login* endpoints are modeled (see the auth
//! section) and are the most uncertain part of the file.
//!
//! # Rules this module enforces
//!
//! - **One attempt.** Nothing here retries a failed login. A loop against an
//!   MFA challenge is how a bank account gets locked.
//! - **Polite pacing.** Reads are spaced by [`MIN_REQUEST_GAP`].
//! - **A status code is not success.** [`json_response`] treats
//!   HTML-where-JSON-was-expected as an auth failure, because that is what a
//!   bounced/Cloudflare-challenged session actually looks like.
//! - **A download is not a document until it matches `%PDF`** — the mechanism
//!   lives in `pk_cli_documents::verify`.

use std::cell::Cell;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pk_cli_core::CliError;
use pk_cli_documents::verify_download;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::API_BASE;

/// A realistic browser User-Agent. Community projects report that SoFi sits
/// behind Cloudflare bot protection, which blocks a non-browser UA outright —
/// so a browser-shaped UA is load-bearing, not cosmetic (docs/api.md §5).
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/// The Apollo client name the banking web app sends on GraphQL calls. SoFi's
/// BFF keys off it; community captures show `banking-accounts-ui`
/// (docs/api.md §3.4).
const APOLLO_CLIENT: &str = "banking-accounts-ui";
/// A client version to accompany the client name — some Apollo BFFs require
/// the pair. Modeled, not observed; overridden by a captured recipe.
const APOLLO_CLIENT_VERSION: &str = "1.0.0";
/// The app origin. A same-site BFF's CSRF check commonly requires `Origin`
/// (and `Referer`) to match; a cookies-only request that omits them is a
/// prime suspect for the live 403 (docs/api.md §3.4).
const APP_ORIGIN: &str = "https://www.sofi.com";
/// A plausible in-app referer for the same reason.
const APP_REFERER: &str = "https://www.sofi.com/my/money/";
/// The default CSRF header name. The real name is confirmed by the browser
/// login's header-recipe capture (docs/api.md §3.4); until then this is the
/// community-modeled spelling.
const DEFAULT_CSRF_HEADER: &str = "csrf-token";

/// Minimum spacing between requests — cheap insurance against a throttle.
const MIN_REQUEST_GAP: Duration = Duration::from_millis(300);

/// Accounts collection: balances, APY, and the YTD/lifetime interest figures.
pub const ACCOUNTS_PATH: &str = "/money/api/public/v2/accounts";
/// Statements collection (combined PDFs).
pub const STATEMENTS_PATH: &str = "/banking-service/api/public/v2/statements";
/// The GraphQL BFF — transactions live here, not in a REST collection.
pub const GRAPHQL_PATH: &str = "/bff/graphql";

/// The Auth0 Universal Login page the browser login opens. `login.sofi.com`
/// (not the app origin) is where the password + MFA form lives.
pub const LOGIN_PAGE_URL: &str = "https://login.sofi.com/u/login";

/// The HttpOnly bearer cookie SoFi sets on the app origin only **after** a
/// successful login. Its presence is the "signed in" signal the browser
/// harvest gates on (docs/api.md §2.4).
pub const SESSION_COOKIE: &str = "SOFI";
/// The readable cookie that doubles as the CSRF token GraphQL POSTs echo.
pub const CSRF_COOKIE: &str = "SOFI_R_CSRF_TOKEN";

/// **DEAD-LIVE (probed 2026-08-24): `POST /login-service/v1/login` answered
/// HTTP 404 — this modeled endpoint does not exist.** SoFi's real login is the
/// Auth0 + Cloudflare + ThreatMetrix front door, which cannot be driven
/// headlessly; use `sfi auth login --browser` (browser cookie harvest, §2)
/// instead. Kept only so the `--code` resume path compiles for the day (if
/// ever) a scriptable endpoint materializes. See docs/api.md §2.6.
pub const LOGIN_PATH: &str = "/login-service/v1/login";
/// **DEAD-LIVE (2026-08-24)** — see [`LOGIN_PATH`].
pub const VERIFY_PATH: &str = "/login-service/v1/login/verify";

/// The path the browser login reads to confirm a harvested session actually
/// works. Defaults to the accounts collection, but that endpoint is itself
/// UNVERIFIED-LIVE, so it is **swappable** via `SFI_VALIDATE_PATH` — once the
/// owner signs in, a live probe (`sfi api GET <path>`) can point validation at
/// whatever mild read turns out to exist, without a rebuild (docs/api.md §2.5).
pub fn validation_path() -> String {
    validation_path_from(std::env::var("SFI_VALIDATE_PATH").ok())
}

/// [`validation_path`] for a given `SFI_VALIDATE_PATH` value: the value when
/// it is set and non-empty, else the accounts collection. Pure, so the
/// fallback is tested without touching the environment.
fn validation_path_from(configured: Option<String>) -> String {
    configured
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ACCOUNTS_PATH.to_string())
}

/// Where a verification code should be sent, when the provider offers a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Sms,
    Email,
}

impl Channel {
    fn as_str(self) -> &'static str {
        match self {
            Channel::Sms => "sms",
            Channel::Email => "email",
        }
    }
}

/// The cookies that carry a SoFi session, kept by name so the client can
/// reconstruct the `Cookie` header and the CSRF token every read needs.
///
/// Stored as JSON in the keychain. `SOFI`/`SOFI_SESSION` are the HttpOnly
/// bearer credential; `SOFI_R_CSRF_TOKEN` doubles as the CSRF token the
/// GraphQL POST must echo (docs/api.md §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// The full `Cookie` header value: `name=value; name2=value2; …`.
    pub cookie: String,
    /// Value of `SOFI_R_CSRF_TOKEN`, sent as the `csrf-token` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    /// Absolute expiry in Unix seconds, when the login response gave one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The GraphQL header recipe observed from a real `/bff/graphql` request
    /// during the browser login (docs/api.md §3.4). When present, the client
    /// reproduces the app's exact CSRF header **name** and cookie **source**
    /// instead of guessing — the fix for the live 403. Absent until a login
    /// captures it; then the client falls back to the modeled defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graphql_recipe: Option<GraphqlRecipe>,
}

/// The recipe for reproducing the SoFi app's own `/bff/graphql` request
/// headers. Carries **no secret values** — only header names and which
/// harvested cookie the CSRF header's value is copied from — so it is safe to
/// persist alongside the (already sensitive) session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlRecipe {
    /// The request header names the app sent (lowercased), minus the ones the
    /// HTTP client manages itself (cookie, host, content-length, …).
    ///
    /// **Diagnostic-only — not replayed.** The client supplies its own values
    /// for the headers it knows (`apollographql-*`, `origin`, `referer`,
    /// `accept`) and cannot reproduce an unknown header without its value
    /// (which is deliberately not stored). This field exists so the operator /
    /// a future probe can see the app's real header set; the load-bearing part
    /// of the recipe is the CSRF mapping below.
    pub header_names: Vec<String>,
    /// The header that carries the CSRF token (e.g. `csrf-token`,
    /// `x-csrf-token`), when one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_header: Option<String>,
    /// Which harvested cookie the CSRF header's value came from (e.g.
    /// `SOFI_R_CSRF_TOKEN`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_cookie: Option<String>,
    /// Whether that cookie value was URL-decoded to form the header value.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub csrf_url_decoded: bool,
}

/// The SoFi cookies a session keeps; everything else in the jar is dropped.
const KEPT_COOKIES: [&str; 4] = [SESSION_COOKIE, "SOFI_SESSION", "SOFI_LOGIN", CSRF_COOKIE];

impl Session {
    /// Build a session from `(name, value)` cookie pairs, keeping only the
    /// cookies SoFi's reads depend on and extracting the CSRF token.
    ///
    /// Returns `None` when the bearer cookie is absent — which is how "cookies
    /// present but not actually signed in" surfaces as an error at the call
    /// site rather than an empty session. The single builder shared by the
    /// Set-Cookie harvest and the browser cookie harvest.
    pub fn from_pairs<I, S>(pairs: I) -> Option<Session>
    where
        I: IntoIterator<Item = (S, S)>,
        S: AsRef<str>,
    {
        let mut kept: Vec<(String, String)> = Vec::new();
        let mut csrf = None;
        for (name, value) in pairs {
            let name = name.as_ref().trim();
            let value = value.as_ref().trim();
            if !KEPT_COOKIES.contains(&name) {
                continue;
            }
            if name == CSRF_COOKIE {
                csrf = Some(value.to_string());
            }
            kept.push((name.to_string(), value.to_string()));
        }
        // The real bearer cookie must be present; SOFI_LOGIN alone is a flag,
        // not a credential.
        if !kept.iter().any(|(n, _)| n == SESSION_COOKIE) {
            return None;
        }
        let cookie = kept
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        Some(Session {
            cookie,
            csrf_token: csrf,
            expires_at: None,
            graphql_recipe: None,
        })
    }

    /// The `(name, value)` pairs of this session's `Cookie` header — the
    /// **one** parser of that wire format, so the recipe's cookie match and the
    /// client's replay can never disagree about splitting it.
    pub fn cookie_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.cookie
            .split(';')
            .filter_map(|pair| pair.trim().split_once('='))
    }

    /// The value of a named cookie in this session's `Cookie` header.
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.cookie_pairs()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.to_string())
    }

    /// Build a session from a set of `Set-Cookie` header lines (a login
    /// response's, say). A line is `name=value; Path=…; HttpOnly; …`; only the
    /// leading `name=value` matters.
    pub fn from_set_cookies(lines: &[String]) -> Option<Session> {
        Session::from_pairs(lines.iter().filter_map(|line| {
            line.split(';')
                .next()
                .and_then(|p| p.trim().split_once('='))
                .map(|(n, v)| (n.to_string(), v.to_string()))
        }))
    }

    /// Build a session from a `"name=value; name=value"` cookie bundle, the
    /// shorthand the tests write sessions in. The browser login builds its
    /// session from the captured jar's pairs with [`Session::from_pairs`].
    #[cfg(test)]
    pub fn from_bundle(bundle: &str) -> Option<Session> {
        Session::from_pairs(bundle.split(';').filter_map(|pair| {
            pair.trim()
                .split_once('=')
                .map(|(n, v)| (n.to_string(), v.to_string()))
        }))
    }

    pub fn from_json(raw: &str) -> Result<Self, CliError> {
        serde_json::from_str(raw).map_err(|e| {
            CliError::Auth(format!(
                "the cached session could not be read ({e}) — run `sfi auth login` again"
            ))
        })
    }

    pub fn to_secret(&self) -> pk_cli_secrets::Secret {
        pk_cli_secrets::Secret::new(serde_json::to_string(self).unwrap_or_default())
    }

    /// Whether the session is past (or within a minute of) a known expiry. A
    /// session with no known expiry is reported usable — the server stays the
    /// authority, and guessing "expired" would force a needless login.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => exp.saturating_sub(60) <= now_unix(),
            None => false,
        }
    }

    pub fn expires_at_rfc3339(&self) -> Option<String> {
        self.expires_at
            .map(|e| pk_cli_core::dates::fmt_rfc3339(e as i64))
    }
}

/// A login that stopped on an MFA challenge and can be resumed.
///
/// Persisted (JSON) in the keychain under `pending`. Carries no secret: the
/// password it re-presents comes from the keychain, and these ids are
/// meaningless without it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parked {
    /// The provider's challenge/transaction id, echoed on the verify call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token: Option<String>,
    /// The device id this attempt presented; reused on resume so the provider
    /// sees the same device.
    pub device_id: String,
    /// Where the code was sent.
    pub channel: Channel,
}

/// What one login attempt produced.
#[derive(Debug)]
pub enum LoginOutcome {
    /// Authenticated outright (a remembered device, or a resumed attempt).
    Session(Box<Session>),
    /// Stopped on an SMS/email verification code.
    NeedsCode { parked: Box<Parked>, hint: String },
}

/// The pure decision a login/verify response body drives, split out so the
/// branch logic — the part that changes when SoFi reshapes its auth — is
/// unit-testable offline against fixtures, with no network involved.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginStep {
    /// Credentials accepted, no second factor outstanding — the caller builds
    /// the session from the response's `Set-Cookie` headers.
    Authenticated,
    /// A second factor is required; carries the challenge token to park.
    NeedsCode { mfa_token: Option<String> },
}

/// Client for SoFi's private API.
pub struct Sofi {
    http: reqwest::blocking::Client,
    base: String,
    last_request: Cell<Option<Instant>>,
}

impl Sofi {
    pub fn new() -> Result<Self, CliError> {
        Self::with_base(API_BASE)
    }

    /// Build a client against an explicit base URL. `new()` is
    /// `with_base(API_BASE)`; a test can point it at a loopback server to
    /// drive `get`/`get_document`/`graphql` offline without touching SoFi or
    /// the keychain.
    pub fn with_base(base: impl Into<String>) -> Result<Self, CliError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Accept", "application/json".parse().unwrap());
        headers.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());

        // Deliberately no reqwest cookie jar: sessions are handled by hand
        // (`Session::from_set_cookies` harvests a login response's Set-Cookie
        // lines; reads replay an explicit `Cookie` header). A jar would be a
        // second, invisible home for the same state. Whether SoFi sets cookies
        // on a login 302 hop that a final-response harvest would miss is a
        // live-capture follow-up (docs/api.md §2, §7).
        let http = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| CliError::Other(format!("failed to build HTTP client: {e}")))?;
        Ok(Sofi {
            http,
            base: base.into(),
            last_request: Cell::new(None),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// Space requests out, so a burst of pagination can't trip a throttle.
    fn pace(&self) {
        if let Some(last) = self.last_request.get() {
            let elapsed = last.elapsed();
            if elapsed < MIN_REQUEST_GAP {
                std::thread::sleep(MIN_REQUEST_GAP - elapsed);
            }
        }
        self.last_request.set(Some(Instant::now()));
    }

    /// Mint a device id. A v4 UUID shape, generated once per install and then
    /// persisted forever: regenerating it presents as a brand-new device and
    /// re-raises the MFA challenge.
    pub fn new_device_id() -> String {
        // A dependency-free v4-shaped id from the clock and address entropy —
        // uniqueness is all that matters here, not cryptographic randomness.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let salt = &nanos as *const _ as usize as u128;
        let mut x = nanos ^ (salt << 64) ^ 0x9E37_79B9_7F4A_7C15;
        let mut hex = String::with_capacity(32);
        for _ in 0..32 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            hex.push(char::from_digit((x & 0xf) as u32, 16).unwrap_or('0'));
        }
        let b = hex.as_bytes();
        let s = |lo: usize, hi: usize| std::str::from_utf8(&b[lo..hi]).unwrap();
        // Force the version/variant nibbles so it is a well-formed v4 shape.
        format!(
            "{}-{}-4{}-8{}-{}",
            s(0, 8),
            s(8, 12),
            s(13, 16),
            s(17, 20),
            s(20, 32)
        )
    }

    // -------------------------------------------------------------- auth

    /// Attempt a password login. **One** request; never loops.
    ///
    /// UNVERIFIED-LIVE: the request/response shapes are modeled (docs/api.md
    /// §2). The response's cookies build the session; its body decides whether
    /// a second factor is outstanding.
    pub fn login(
        &self,
        username: &str,
        password: &str,
        device_id: &str,
        channel: Channel,
    ) -> Result<LoginOutcome, CliError> {
        let body = json!({
            "username": username,
            "password": password,
            "deviceId": device_id,
            "rememberDevice": true,
            "channel": channel.as_str(),
        });
        let (set_cookies, v, status) = self.post_capturing_cookies(LOGIN_PATH, &body)?;
        match interpret_login(&v, status)? {
            LoginStep::Authenticated => {
                let session = Session::from_set_cookies(&set_cookies).ok_or_else(|| {
                    CliError::Auth(
                        "SoFi accepted the login but returned no session cookie — the login flow \
                         has probably changed shape; see docs/api.md §2"
                            .into(),
                    )
                })?;
                Ok(LoginOutcome::Session(Box::new(session)))
            }
            LoginStep::NeedsCode { mfa_token } => Ok(LoginOutcome::NeedsCode {
                parked: Box::new(Parked {
                    mfa_token,
                    device_id: device_id.to_string(),
                    channel,
                }),
                hint: format!("SoFi sent a verification code by {}", channel.as_str()),
            }),
        }
    }

    /// Resume a parked attempt by answering its verification code.
    ///
    /// Exactly one pass; if it fails, it fails. UNVERIFIED-LIVE (docs/api.md
    /// §2).
    pub fn verify_code(&self, parked: &Parked, code: &str) -> Result<Session, CliError> {
        let body = json!({
            "code": code,
            "mfaToken": parked.mfa_token,
            "deviceId": parked.device_id,
            "rememberDevice": true,
        });
        let (set_cookies, v, _status) = self.post_capturing_cookies(VERIFY_PATH, &body)?;
        // The provider may answer 200 for a rejected code, carrying the real
        // outcome in the body — so cookies, not the status, decide success.
        // Absence of the bearer cookie is the rejection signal.
        Session::from_set_cookies(&set_cookies).ok_or_else(|| {
            CliError::Auth(format!(
                "SoFi rejected the verification code{}",
                detail_suffix(&v)
            ))
        })
    }

    /// POST JSON, returning the response's `Set-Cookie` lines, parsed body,
    /// and status — the raw materials both auth steps interpret.
    fn post_capturing_cookies(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<(Vec<String>, Value, u16), CliError> {
        self.pace();
        let resp = self
            .http
            .post(self.url(path))
            .json(body)
            .send()
            .map_err(|e| CliError::Upstream(format!("contacting SoFi: {e}")))?;
        let status = resp.status().as_u16();
        // The Set-Cookie lines of the **final** response hop. If SoFi turns out
        // to set session cookies on an intermediate 302 of the login/verify
        // dance, this would miss them — a known limitation to confirm against a
        // live capture (docs/api.md §2, §7); this whole login flow is modeled.
        let set_cookies: Vec<String> = resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect();
        let text = resp
            .text()
            .map_err(|e| CliError::Upstream(format!("reading login response: {e}")))?;
        // Deliberately NOT the shared `classify_status` ladder: a login/verify
        // 4xx can still carry an MFA challenge, so every non-2xx-but-not-429
        // body is handed to `interpret_login`, which owns the login-specific
        // decision (challenge vs. rejection). Only a 429 throttle short-circuits
        // here — it is never a login shape.
        if status == 429 {
            return Err(throttled());
        }
        let v = parse_json(&text, status)?;
        Ok((set_cookies, v, status))
    }

    // -------------------------------------------------------------- reads

    /// Authenticated GET returning parsed JSON. Presents the session cookies.
    pub fn get(
        &self,
        session: &Session,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Value, CliError> {
        self.pace();
        let resp = self
            .http
            .get(url)
            .header(reqwest::header::COOKIE, &session.cookie)
            .query(query)
            .send()
            .map_err(|e| CliError::Upstream(format!("calling {url}: {e}")))?;
        json_response(resp)
    }

    /// Authenticated GET returning raw bytes, verified as a PDF before they
    /// are handed back. Used for statement downloads.
    pub fn get_document(&self, session: &Session, url: &str) -> Result<Vec<u8>, CliError> {
        self.pace();
        let resp = self
            .http
            .get(url)
            .header(reqwest::header::COOKIE, &session.cookie)
            .header(
                reqwest::header::ACCEPT,
                "text/html,application/xhtml+xml,application/pdf,*/*;q=0.8",
            )
            .send()
            .map_err(|e| CliError::Upstream(format!("downloading {url}: {e}")))?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        // The same status ladder every read uses (one definition).
        if let Some(err) = classify_status(status, &final_url, &Value::Null) {
            return Err(err);
        }
        let bytes = resp
            .bytes()
            .map_err(|e| CliError::Upstream(format!("reading document body: {e}")))?
            .to_vec();
        // A lapsed session (or a Cloudflare interstitial) answers 200 with an
        // HTML login page where a PDF was promised: an auth failure (exit 3),
        // not the exit-5 "fetch a fresh link" `verify_download` reports for a
        // genuinely expired pre-signed link. This distinction is the pure,
        // tested `document_auth_failure`.
        if let Some(err) = document_auth_failure(&bytes, &final_url) {
            return Err(err);
        }
        // Statements are always PDFs; anything that isn't (a JSON/XML error
        // from an expired pre-signed link) is a genuine upstream problem.
        verify_download(&bytes, Some("pdf"))?;
        Ok(bytes)
    }

    /// The extra request headers a `/bff/graphql` POST sends (beyond the
    /// `Cookie` reqwest attaches and the JSON `Content-Type`): the Apollo
    /// client name/version, the same-site `Origin`/`Referer` a CSRF check
    /// commonly requires, `Accept`, and the CSRF header.
    ///
    /// If the session carries a captured [`GraphqlRecipe`], the CSRF header's
    /// **name** and cookie **source** come from what the app actually sent
    /// (the live-403 fix); otherwise the modeled defaults are used. Pure and
    /// POST a GraphQL operation to the BFF. Returns the `data` object.
    pub fn graphql(
        &self,
        session: &Session,
        operation: &str,
        query: &str,
        variables: Value,
    ) -> Result<Value, CliError> {
        self.pace();
        let body = json!({
            "operationName": operation,
            "variables": variables,
            "query": query,
        });
        let sent = graphql_headers(session);
        let mut req = self
            .http
            .post(self.url(GRAPHQL_PATH))
            .header(reqwest::header::COOKIE, &session.cookie)
            .json(&body);
        for (name, value) in &sent {
            req = req.header(name.as_str(), value.as_str());
        }
        let resp = req
            .send()
            .map_err(|e| CliError::Upstream(format!("calling the SoFi GraphQL BFF: {e}")))?;

        let (status, url, text) = response_parts(resp)?;

        // A lapsed session / Cloudflare interstitial is HTML, not JSON.
        if looks_like_html(&text) {
            if status == 403 || html_reads_as_edge_block(&text) {
                return Err(edge_block(status));
            }
            return Err(CliError::Auth(format!(
                "the GraphQL BFF answered HTML (HTTP {status}) — the session has probably lapsed; \
                 run `sfi auth login --browser`"
            )));
        }
        // A 403 is a CSRF/header problem, not an expiry — but it stays exit 3
        // (`Auth`), matching `classify_status`'s ladder, because the actionable
        // fix *is* `sfi auth login --browser` (which recaptures the header
        // recipe). Only the message is overridden, to the self-explaining
        // diagnostic instead of the generic one. See docs/api.md §3.4.
        if status == 403 {
            return Err(CliError::Auth(graphql_403_diagnostic(session, &sent)));
        }
        let v = classify_and_parse(status, &url, &text)?;

        // A GraphQL error is a 200 with an `errors` array — never trust the
        // status alone (docs/api.md §3.4).
        if let Some(errors) = v.get("errors").and_then(Value::as_array) {
            if !errors.is_empty() {
                let msg = errors
                    .first()
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown GraphQL error");
                // An auth-shaped GraphQL error is an expiry, not an upstream bug.
                if msg.to_lowercase().contains("unauth") || msg.to_lowercase().contains("session") {
                    return Err(CliError::Auth(format!(
                        "SoFi's GraphQL BFF rejected the session: {msg} — run `sfi auth login \
                         --browser`"
                    )));
                }
                return Err(CliError::Upstream(format!(
                    "SoFi's GraphQL BFF returned an error: {msg}"
                )));
            }
        }
        v.get("data").cloned().ok_or_else(|| {
            CliError::Upstream("the GraphQL response carried no data — see docs/api.md §3.4".into())
        })
    }

    /// Resolve a path against the API base (absolute URLs pass through).
    pub fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            format!("{}{}", self.base.trim_end_matches('/'), path)
        }
    }
}

/// The extra request headers a `/bff/graphql` POST sends (beyond the `Cookie`
/// reqwest attaches and the JSON `Content-Type`): the Apollo client
/// name/version, the same-site `Origin`/`Referer` a CSRF check commonly
/// requires, `Accept`, and the CSRF header.
///
/// If the session carries a captured [`GraphqlRecipe`], the CSRF header's
/// **name** and cookie **source** come from what the app actually sent (the
/// live-403 fix); otherwise the modeled defaults are used. The recipe's
/// `header_names` are **not** replayed — they are a diagnostic record (the
/// client supplies its own values for the headers it knows). Pure and
/// offline-tested, so it takes only a `&Session`.
pub fn graphql_headers(session: &Session) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "apollographql-client-name".to_string(),
            APOLLO_CLIENT.to_string(),
        ),
        (
            "apollographql-client-version".to_string(),
            APOLLO_CLIENT_VERSION.to_string(),
        ),
        ("origin".to_string(), APP_ORIGIN.to_string()),
        ("referer".to_string(), APP_REFERER.to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];

    // The CSRF header: recipe-driven when we observed the app's real request,
    // else the modeled `csrf-token` = `SOFI_R_CSRF_TOKEN` cookie.
    let (csrf_header, csrf_value) = match &session.graphql_recipe {
        Some(r) => {
            let name = r
                .csrf_header
                .clone()
                .unwrap_or_else(|| DEFAULT_CSRF_HEADER.to_string());
            let raw = r
                .csrf_cookie
                .as_deref()
                .and_then(|c| session.cookie_value(c))
                .or_else(|| session.csrf_token.clone());
            let value = raw.map(|v| {
                if r.csrf_url_decoded {
                    percent_decode(&v)
                } else {
                    v
                }
            });
            (name, value)
        }
        None => (
            DEFAULT_CSRF_HEADER.to_string(),
            session
                .csrf_token
                .clone()
                .or_else(|| session.cookie_value(CSRF_COOKIE)),
        ),
    };
    if let Some(value) = csrf_value {
        headers.push((csrf_header, value));
    }
    headers
}

/// The self-explaining diagnostic for a `/bff/graphql` 403: which header
/// inputs the request carried, so the next probe (or a bug report) needs no
/// guessing. Names only — never a cookie or token value.
fn graphql_403_diagnostic(session: &Session, sent: &[(String, String)]) -> String {
    let sent_names: Vec<&str> = sent.iter().map(|(n, _)| n.as_str()).collect();
    let cookie_names: Vec<&str> = session.cookie_pairs().map(|(n, _)| n).collect();
    let csrf_present = sent.iter().any(|(n, _)| n.to_lowercase().contains("csrf"));
    let recipe = if session.graphql_recipe.is_some() {
        "a captured header recipe was applied"
    } else {
        "no header recipe captured (modeled defaults used)"
    };
    format!(
        "SoFi's GraphQL BFF returned HTTP 403 with the harvested session. Sent request \
         headers: [{}]. CSRF header {}. Cookies present: [{}]. {recipe}. This is almost \
         certainly a header issue, not an expired login: the app likely uses a different \
         CSRF header name/source, or requires Origin/Referer. Fix by re-running `sfi auth \
         login --browser`, which records the app's real /bff/graphql header recipe \
         (docs/api.md §3.4); or capture a /bff/graphql request's headers in Chrome DevTools \
         and report their names.",
        sent_names.join(", "),
        if csrf_present {
            "was present"
        } else {
            "was ABSENT (no SOFI_R_CSRF_TOKEN cookie harvested)"
        },
        cookie_names.join(", "),
    )
}

/// Minimal percent-decoding for a cookie value reused as a header (some CSRF
/// cookies are percent-encoded base64, and the header wants the decoded form).
/// Handles `%XX` escapes; leaves everything else untouched.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decide what a login/verify response body means. Pure and offline-tested.
///
/// UNVERIFIED-LIVE: the marker fields are modeled (docs/api.md §2). Success is
/// "no outstanding second factor"; the presence of an MFA marker means a code
/// is required; an explicit error is an auth failure.
pub fn interpret_login(v: &Value, status: u16) -> Result<LoginStep, CliError> {
    // An MFA challenge, in any of the shapes a login service tends to use.
    let mfa_required = v.get("mfaRequired").and_then(Value::as_bool) == Some(true)
        || v.get("challenge").is_some()
        || v.get("mfaToken").is_some()
        || v.get("status").and_then(Value::as_str) == Some("MFA_REQUIRED");
    if mfa_required {
        let mfa_token = v
            .get("mfaToken")
            .and_then(Value::as_str)
            .or_else(|| v.pointer("/challenge/id").and_then(Value::as_str))
            .or_else(|| v.get("transactionId").and_then(Value::as_str))
            .map(str::to_string);
        return Ok(LoginStep::NeedsCode { mfa_token });
    }

    // An explicit error body is an auth failure, whatever the status.
    if let Some(err) = v
        .get("error")
        .and_then(Value::as_str)
        .or_else(|| v.get("errorCode").and_then(Value::as_str))
    {
        return Err(CliError::Auth(format!(
            "SoFi did not complete the login: {err}{}",
            detail_suffix(v)
        )));
    }

    // A 4xx with no recognized challenge is a rejection, not success.
    if !(200..300).contains(&status) {
        return Err(CliError::Auth(format!(
            "SoFi rejected the login (HTTP {status}){} — check the username and password",
            detail_suffix(v)
        )));
    }

    Ok(LoginStep::Authenticated)
}

/// The exit-code contract for an HTTP status, in **one** place so the JSON
/// read path, the document download, and any future caller can never drift on
/// "401 is auth, 429 is throttle, 404 is not-found, other non-2xx is upstream".
/// Returns `None` for a 2xx (the caller proceeds). `detail` is the parsed body
/// when available, for the provider's own error message; pass `Value::Null`
/// when there is none (e.g. a binary download).
///
/// The HTML-where-data-was-expected check is **not** here: it is body-shaped,
/// not status-shaped, and each caller applies it against its own body (text
/// vs. bytes) before consulting this ladder.
pub fn classify_status(status: u16, url: &str, detail: &Value) -> Option<CliError> {
    match status {
        429 => Some(throttled()),
        401 => Some(CliError::Auth(format!(
            "SoFi rejected the request (HTTP {status}) — run `sfi auth login`"
        ))),
        403 => Some(CliError::Auth(
            "SoFi refused the request (HTTP 403): the session may be invalid, or this may be \
             a bot check or edge block. If a sign-in just met this, wait before trying again, \
             since a retry now may hit the same block; otherwise run `sfi auth login \
             --browser`"
                .into(),
        )),
        404 => Some(CliError::NotFound(format!("HTTP 404 from {url}"))),
        s if !(200..300).contains(&s) => Some(CliError::Upstream(format!(
            "SoFi returned HTTP {s}{}",
            detail_suffix(detail)
        ))),
        _ => None,
    }
}

/// Whether a downloaded document body is actually an HTML login page — a
/// lapsed session (or a Cloudflare interstitial) answering `200` where a PDF
/// was promised. Returns the same auth error the JSON path returns, so a
/// download and a read agree that "HTML where data was expected" is exit 3,
/// not the exit-5 that `verify_download` reports for a genuinely expired
/// pre-signed link. Pure, so the branch is unit-tested without a live response.
pub fn document_auth_failure(bytes: &[u8], url: &str) -> Option<CliError> {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]);
    looks_like_html(&head).then(|| {
        CliError::Auth(format!(
            "expected a PDF from {} but got an HTML page — the session has probably lapsed \
             (or Cloudflare is challenging this client); run `sfi auth login`",
            without_query(url)
        ))
    })
}

/// Read a response into `(status, url, body_text)` — the raw materials every
/// JSON caller interprets, shared so the read path and the GraphQL path can't
/// drift on how a response is drained.
fn response_parts(resp: reqwest::blocking::Response) -> Result<(u16, String, String), CliError> {
    let status = resp.status().as_u16();
    let url = resp.url().to_string();
    let text = resp
        .text()
        .map_err(|e| CliError::Upstream(format!("reading response body: {e}")))?;
    Ok((status, url, text))
}

/// The shared tail every JSON caller runs once its own body-shaped checks
/// (HTML, and GraphQL's 403 special-case) have passed: the **one** status
/// ladder ([`classify_status`]) then the parse. So there is a single exit-code
/// contract, and `graphql`'s only deliberate deviation is its 403 message
/// override (still exit 3, `Auth` — see `graphql`).
fn classify_and_parse(status: u16, url: &str, text: &str) -> Result<Value, CliError> {
    let parsed: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    if let Some(err) = classify_status(status, url, &parsed) {
        return Err(err);
    }
    parse_json(text, status)
}

/// Map a response onto the exit-code contract, treating HTML as an auth
/// failure rather than trusting the status code.
pub fn json_response(resp: reqwest::blocking::Response) -> Result<Value, CliError> {
    let (status, url, text) = response_parts(resp)?;

    // A lapsed session — or a Cloudflare interstitial — frequently comes back
    // as an HTML page with a 200, not a 401. So shape, not status, decides,
    // and this body-shaped check runs before the status ladder.
    if looks_like_html(&text) {
        if matches!(status, 403 | 429 | 503) || html_reads_as_edge_block(&text) {
            return Err(edge_block(status));
        }
        return Err(CliError::Auth(format!(
            "expected JSON from {} but got an HTML page (HTTP {status}) — the session has \
             probably lapsed (or Cloudflare is challenging this client); run `sfi auth login`",
            without_query(&url)
        )));
    }
    classify_and_parse(status, &url, &text)
}

fn parse_json(text: &str, status: u16) -> Result<Value, CliError> {
    if looks_like_html(text) {
        return Err(CliError::Auth(format!(
            "expected JSON but got an HTML page (HTTP {status}) — run `sfi auth login`"
        )));
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text)
        .map_err(|e| CliError::Upstream(format!("parsing SoFi JSON (HTTP {status}): {e}")))
}

fn looks_like_html(text: &str) -> bool {
    // Slice as bytes: a byte-index slice of the &str itself panics when 256
    // lands inside a multi-byte character. Lossy is fine — the markers are
    // ASCII.
    let head = text.trim_start().as_bytes();
    let lower = String::from_utf8_lossy(&head[..head.len().min(256)]).to_lowercase();
    lower.starts_with("<!doctype html") || lower.starts_with("<html") || lower.starts_with("<?xml")
}

/// A URL for a message, without its query or fragment: a redirect to the login page
/// carries a state value there, and a pre-signed link its signature.
fn without_query(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// The words only [`edge_block`] uses, so a sign-in's hook can tell that refusal from
/// the others, which all arrive as the same `Auth`.
pub const EDGE_BLOCK: &str = "possibly a bot check or edge block";

/// Whether a refusal's text is [`edge_block`]'s.
pub fn names_an_edge_block(refusal: &str) -> bool {
    refusal.contains(EDGE_BLOCK)
}

/// An HTML page from the edge where data was expected: a possible bot check, which
/// a fresh sign-in may run straight into. Exit 3, as any refusal is, but not worded
/// as an expired session. It names the status only, never the page.
fn edge_block(status: u16) -> CliError {
    CliError::Auth(format!(
        "SoFi answered with an HTML page (HTTP {status}): {EDGE_BLOCK}, not an expired \
         session. Wait before signing in again, since a retry now may \
         hit the same block; then run `sfi auth login --browser`"
    ))
}

/// Whether an HTML page reads as a bot check or an edge block rather than a login
/// page: a challenge's own wording, in the head of the page. Not a login page's
/// reCAPTCHA or Turnstile, which every sign-in shows.
fn html_reads_as_edge_block(text: &str) -> bool {
    let head = String::from_utf8_lossy(&text.as_bytes()[..text.len().min(8192)]).to_lowercase();
    [
        "just a moment",
        "attention required",
        "cf-chl",
        "access denied",
    ]
    .iter()
    .any(|marker| head.contains(marker))
}

/// A throttle is upstream (exit 5), and waiting is the actionable part.
fn throttled() -> CliError {
    CliError::Upstream("SoFi is rate limiting this client (HTTP 429) — wait before retrying".into())
}

/// The provider's own message, when it gave one. Never includes the request
/// body (which holds the password).
fn detail_suffix(v: &Value) -> String {
    for key in ["message", "detail", "error_description", "errorMessage"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return format!(": {s}");
            }
        }
    }
    String::new()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sofi() -> Sofi {
        Sofi::new().expect("client builds")
    }

    #[test]
    fn a_clean_200_with_no_challenge_is_authenticated() {
        assert_eq!(
            interpret_login(&json!({"status": "OK"}), 200).unwrap(),
            LoginStep::Authenticated
        );
    }

    #[test]
    fn an_mfa_marker_asks_for_a_code_and_parks_its_token() {
        for body in [
            json!({"mfaRequired": true, "mfaToken": "tok-123"}),
            json!({"status": "MFA_REQUIRED", "transactionId": "tok-123"}),
            json!({"challenge": {"id": "tok-123", "type": "sms"}}),
        ] {
            match interpret_login(&body, 200).unwrap() {
                LoginStep::NeedsCode { mfa_token } => {
                    assert_eq!(mfa_token.as_deref(), Some("tok-123"), "{body}");
                }
                other => panic!("expected NeedsCode, got {other:?} for {body}"),
            }
        }
    }

    #[test]
    fn an_explicit_error_body_is_an_auth_failure() {
        let err = interpret_login(&json!({"error": "invalid_credentials"}), 200).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("invalid_credentials"));
    }

    #[test]
    fn a_4xx_without_a_challenge_is_a_rejection_not_success() {
        let err = interpret_login(&json!({}), 401).unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn a_session_is_built_only_when_the_bearer_cookie_is_present() {
        let lines = vec![
            "SOFI=abc123; Path=/; HttpOnly; Secure".to_string(),
            "SOFI_SESSION=hash-uuid=xyz; Path=/; HttpOnly".to_string(),
            "SOFI_LOGIN=1; Path=/".to_string(),
            "SOFI_R_CSRF_TOKEN=csrf-tok; Path=/".to_string(),
            "irrelevant=drop; Path=/".to_string(),
        ];
        let s = Session::from_set_cookies(&lines).expect("has SOFI cookie");
        assert!(s.cookie.contains("SOFI=abc123"));
        assert!(s.cookie.contains("SOFI_R_CSRF_TOKEN=csrf-tok"));
        // The irrelevant cookie is dropped.
        assert!(!s.cookie.contains("irrelevant"));
        assert_eq!(s.csrf_token.as_deref(), Some("csrf-tok"));

        // No SOFI cookie → no session (a silent-failure guard).
        assert!(Session::from_set_cookies(&["SOFI_LOGIN=1; Path=/".to_string()]).is_none());
        assert!(Session::from_set_cookies(&[]).is_none());
    }

    #[test]
    fn a_session_round_trips_through_the_keychain_encoding() {
        let s = Session {
            cookie: "SOFI=a; SOFI_R_CSRF_TOKEN=c".into(),
            csrf_token: Some("c".into()),
            expires_at: Some(now_unix() + 3600),
            graphql_recipe: None,
        };
        let back = Session::from_json(s.to_secret().expose()).unwrap();
        assert_eq!(back.cookie, s.cookie);
        assert_eq!(back.csrf_token, s.csrf_token);
        assert_eq!(back.expires_at, s.expires_at);
        assert!(!back.is_expired());
    }

    #[test]
    fn an_unreadable_session_is_an_auth_error_not_a_crash() {
        assert_eq!(Session::from_json("not json").unwrap_err().exit_code(), 3);
    }

    #[test]
    fn expiry_in_the_past_is_expired_and_unknown_defers_to_the_server() {
        let mut s = Session {
            cookie: "SOFI=a".into(),
            csrf_token: None,
            expires_at: None,
            graphql_recipe: None,
        };
        assert!(!s.is_expired(), "unknown expiry defers to the server");
        s.expires_at = Some(now_unix() - 1);
        assert!(s.is_expired());
    }

    #[test]
    fn html_is_treated_as_a_lapsed_session_not_as_data() {
        let err = parse_json("<!DOCTYPE html><html>login</html>", 200).unwrap_err();
        assert_eq!(err.exit_code(), 3, "200-with-HTML is an auth failure");
    }

    #[test]
    fn an_empty_body_parses_as_null_rather_than_failing() {
        assert_eq!(parse_json("", 200).unwrap(), Value::Null);
    }

    #[test]
    fn html_detection_tolerates_whitespace_and_multibyte_tails() {
        assert!(looks_like_html("   \n<html>"));
        assert!(looks_like_html("<!DOCTYPE HTML PUBLIC"));
        assert!(!looks_like_html("{\"accounts\": []}"));
        assert!(!looks_like_html(""));
        let mut long = "<html>".to_string();
        long.push_str(&"a".repeat(249));
        long.push_str("é and more");
        assert!(looks_like_html(&long));
    }

    #[test]
    fn detail_suffix_prefers_the_providers_own_fields() {
        assert_eq!(detail_suffix(&json!({"message": "nope"})), ": nope");
        assert_eq!(detail_suffix(&json!({})), "");
        assert_eq!(detail_suffix(&Value::Null), "");
        // An empty string must not produce a dangling colon.
        assert_eq!(detail_suffix(&json!({"message": ""})), "");
    }

    #[test]
    fn device_ids_are_unique_and_uuid_shaped() {
        let a = Sofi::new_device_id();
        let b = Sofi::new_device_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.matches('-').count(), 4);
        // v4 shape: the version nibble is 4, the variant nibble is 8.
        assert_eq!(a.as_bytes()[14], b'4');
        assert_eq!(a.as_bytes()[19], b'8');
    }

    #[test]
    fn parked_state_round_trips_and_carries_no_secret() {
        let p = Parked {
            mfa_token: Some("tok".into()),
            device_id: "dev".into(),
            channel: Channel::Sms,
        };
        let raw = serde_json::to_string(&p).unwrap();
        assert!(!raw.to_lowercase().contains("password"));
        let back: Parked = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.mfa_token.as_deref(), Some("tok"));
        assert_eq!(back.channel, Channel::Sms);
    }

    #[test]
    fn urls_resolve_against_the_base_and_pass_absolutes_through() {
        let c = sofi();
        assert_eq!(
            c.url(ACCOUNTS_PATH),
            "https://www.sofi.com/money/api/public/v2/accounts"
        );
        assert_eq!(c.url("https://www.sofi.com/x"), "https://www.sofi.com/x");
    }

    #[test]
    fn requests_are_paced() {
        let c = sofi();
        let start = Instant::now();
        c.pace();
        c.pace();
        assert!(start.elapsed() >= MIN_REQUEST_GAP);
    }

    /// `with_base` points the client at an explicit origin, which `new()`
    /// fixes to the live host.
    #[test]
    fn with_base_overrides_the_origin() {
        let c = Sofi::with_base("http://127.0.0.1:9").expect("client builds");
        assert_eq!(c.base(), "http://127.0.0.1:9");
        assert_eq!(c.url("/accounts"), "http://127.0.0.1:9/accounts");
    }

    /// `SFI_VALIDATE_PATH` swaps the validation read; unset or empty (a
    /// common shell artifact) falls back to the accounts collection.
    #[test]
    fn the_validation_path_falls_back_to_the_accounts_collection() {
        assert_eq!(validation_path_from(None), ACCOUNTS_PATH);
        assert_eq!(validation_path_from(Some(String::new())), ACCOUNTS_PATH);
        assert_eq!(
            validation_path_from(Some("/dummy/validation-read".into())),
            "/dummy/validation-read"
        );
    }

    /// The download's HTML-login → auth branch, pure and offline.
    #[test]
    fn document_auth_failure_flags_an_html_login_page() {
        let url = "https://www.sofi.com/statements/x";
        // A 200 body that is an HTML login page → auth (exit 3).
        let err = document_auth_failure(b"<!DOCTYPE html><html>Sign in</html>", url).unwrap();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("auth login"));
        // A real PDF (or any non-HTML) is left to verify_download.
        assert!(document_auth_failure(b"%PDF-1.7\n...", url).is_none());
        assert!(document_auth_failure(b"", url).is_none());
    }

    /// End-to-end through the real `get_document` code path, offline: a
    /// loopback server answers `200 text/html` (a lapsed-session login page)
    /// and the download must surface as auth (exit 3), not upstream. This is
    /// the real consumer `with_base` exists for.
    #[test]
    fn get_document_maps_a_200_html_page_to_auth() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let body = "<!DOCTYPE html><html>Sign in</html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let client = Sofi::with_base(format!("http://127.0.0.1:{port}")).expect("client builds");
        let session = Session {
            cookie: "SOFI=dummy".into(),
            csrf_token: None,
            expires_at: None,
            graphql_recipe: None,
        };
        let err = client
            .get_document(&session, &client.url("/statements/x"))
            .unwrap_err();
        assert_eq!(
            err.exit_code(),
            3,
            "200-HTML on a download is a lapsed session"
        );
        assert!(err.to_string().contains("auth login"));
        let _ = handle.join();
    }

    /// End-to-end through the real `graphql` path: a `403` must surface as
    /// **exit 3** (`Auth`, matching `classify_status`'s ladder — the only
    /// deviation is the richer message), with the self-explaining diagnostic
    /// and no leaked cookie/token values.
    #[test]
    fn graphql_maps_a_403_to_auth_with_the_diagnostic() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let body = r#"{"error":"forbidden"}"#;
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let client = Sofi::with_base(format!("http://127.0.0.1:{port}")).expect("client builds");
        let session =
            Session::from_bundle("SOFI=secretbearer; SOFI_R_CSRF_TOKEN=secrettoken").unwrap();
        let err = client
            .graphql(&session, "Transactions", "query{me}", json!({}))
            .unwrap_err();
        // Same exit code as every other 403 — the ladder isn't reshuffled.
        assert_eq!(err.exit_code(), 3, "a graphql 403 stays auth (exit 3)");
        let msg = err.to_string();
        assert!(msg.contains("403"));
        assert!(msg.contains("auth login --browser"));
        assert!(!msg.contains("secretbearer"), "no cookie value leaks");
        assert!(!msg.contains("secrettoken"), "no csrf value leaks");
        let _ = handle.join();
    }

    #[test]
    fn cookie_pairs_is_the_one_cookie_parser() {
        let s = Session::from_bundle("SOFI=b; SOFI_R_CSRF_TOKEN=tok").unwrap();
        let pairs: Vec<(&str, &str)> = s.cookie_pairs().collect();
        assert!(pairs.contains(&("SOFI", "b")));
        assert!(pairs.contains(&("SOFI_R_CSRF_TOKEN", "tok")));
        // cookie_value is defined in terms of it.
        assert_eq!(s.cookie_value("SOFI").as_deref(), Some("b"));
    }

    #[test]
    fn percent_decode_handles_the_csrf_cookie_escapes() {
        assert_eq!(percent_decode("ab%2Fcd%2Bef%3D"), "ab/cd+ef=");
        assert_eq!(percent_decode("plain"), "plain");
        // A dangling `%` is left as-is rather than panicking.
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn cookie_value_reads_a_named_cookie() {
        let s = Session::from_bundle("SOFI=b; SOFI_R_CSRF_TOKEN=tok").unwrap();
        assert_eq!(s.cookie_value("SOFI").as_deref(), Some("b"));
        assert_eq!(s.cookie_value("SOFI_R_CSRF_TOKEN").as_deref(), Some("tok"));
        assert_eq!(s.cookie_value("nope"), None);
    }

    #[test]
    fn default_graphql_headers_carry_origin_referer_and_the_modeled_csrf() {
        let s = Session::from_bundle("SOFI=b; SOFI_R_CSRF_TOKEN=tok").unwrap();
        let headers = graphql_headers(&s);
        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"origin"), "{names:?}");
        assert!(names.contains(&"referer"), "{names:?}");
        assert!(names.contains(&"apollographql-client-name"));
        // The default CSRF header is `csrf-token` = the SOFI_R_CSRF_TOKEN cookie.
        let csrf = headers
            .iter()
            .find(|(n, _)| n == "csrf-token")
            .expect("csrf header");
        assert_eq!(csrf.1, "tok");
    }

    #[test]
    fn a_captured_recipe_overrides_the_csrf_header_name_and_source() {
        let mut s = Session::from_bundle("SOFI=b; SOFI_R_CSRF_TOKEN=ab%2Fcd").unwrap();
        s.graphql_recipe = Some(GraphqlRecipe {
            header_names: vec!["x-csrf-token".into(), "origin".into()],
            csrf_header: Some("x-csrf-token".into()),
            csrf_cookie: Some("SOFI_R_CSRF_TOKEN".into()),
            csrf_url_decoded: true,
        });
        let headers = graphql_headers(&s);
        // The recipe's header name wins, and the value is the cookie decoded.
        let csrf = headers
            .iter()
            .find(|(n, _)| n == "x-csrf-token")
            .expect("recipe csrf header");
        assert_eq!(csrf.1, "ab/cd");
        // The modeled default header name is not also sent.
        assert!(!headers.iter().any(|(n, _)| n == "csrf-token"));
    }

    #[test]
    fn the_403_diagnostic_names_inputs_without_leaking_values() {
        let s = Session::from_bundle("SOFI=secretbearer; SOFI_R_CSRF_TOKEN=secrettoken").unwrap();
        let sent = graphql_headers(&s);
        let msg = graphql_403_diagnostic(&s, &sent);
        assert!(msg.contains("403"));
        // Names, not values.
        assert!(msg.contains("origin"));
        assert!(msg.contains("SOFI"));
        assert!(
            !msg.contains("secretbearer"),
            "must not leak a cookie value"
        );
        assert!(!msg.contains("secrettoken"), "must not leak the csrf value");
        assert!(msg.contains("auth login --browser"));
    }

    /// The status ladder has exactly one definition; pin the whole contract so
    /// a re-pin or a live-capture fix can't silently reshuffle exit codes.
    /// A challenge page names itself; a login page does not, though it carries a
    /// bot check of its own. A URL in a message drops what could be a value.
    #[test]
    fn an_edge_block_page_reads_differently_from_a_login_page() {
        for page in [
            "<!DOCTYPE html><html><title>Just a moment...</title></html>",
            "<html><title>Attention Required! | Cloudflare</title></html>",
            "<html><script src=\"/cdn-cgi/challenge-platform/cf-chl\"></script></html>",
        ] {
            assert!(html_reads_as_edge_block(page), "{page}");
        }
        for page in [
            "<!DOCTYPE html><html>Sign in</html>",
            "<html><div class=\"g-recaptcha\"></div></html>",
            "<html><script src=\"https://challenges.cloudflare.com/turnstile\"></script></html>",
        ] {
            assert!(!html_reads_as_edge_block(page), "{page}");
        }
        let message = edge_block(403).to_string();
        assert!(message.contains("bot check"), "{message}");
        assert!(message.contains("not an expired session"), "{message}");
        assert_eq!(edge_block(403).exit_code(), 3);

        assert_eq!(
            without_query("https://login.example.com/u/login?state=dummy#frag"),
            "https://login.example.com/u/login"
        );
    }

    #[test]
    fn classify_status_pins_the_exit_code_contract() {
        let url = "https://www.sofi.com/x";
        // 2xx proceeds.
        assert!(classify_status(200, url, &Value::Null).is_none());
        assert!(classify_status(204, url, &Value::Null).is_none());
        // 429 throttle → upstream (5), with a wait hint.
        let e = classify_status(429, url, &Value::Null).unwrap();
        assert_eq!(e.exit_code(), 5);
        // 401/403 → auth (3), pointing at login.
        for s in [401, 403] {
            let e = classify_status(s, url, &Value::Null).unwrap();
            assert_eq!(e.exit_code(), 3);
            assert!(e.to_string().contains("auth login"));
        }
        // 404 → not found (4).
        assert_eq!(
            classify_status(404, url, &Value::Null).unwrap().exit_code(),
            4
        );
        // Other non-2xx → upstream (5), surfacing the provider's own message.
        let e = classify_status(500, url, &json!({"message": "boom"})).unwrap();
        assert_eq!(e.exit_code(), 5);
        assert!(e.to_string().contains("boom"));
    }
}
