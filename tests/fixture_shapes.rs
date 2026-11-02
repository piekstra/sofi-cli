//! Contract tests over `tests/fixtures/`.
//!
//! Two jobs:
//!
//! 1. Assert that the fields the CLI's views actually read are present and
//!    correctly typed, so a modelled-shape mistake (or an upstream rename)
//!    fails the build loudly rather than silently emptying a column.
//! 2. Enforce the synthetic-value policy in `tests/fixtures/README.md`, and
//!    scan the rest of the tracked sources for personal data.
//!
//! The fixtures are synthetic (see the README) — nothing here talks to a
//! network.

use std::path::PathBuf;

use serde_json::Value;

/// Substrings that betray a committed pre-signed URL.
///
/// Assembled at runtime rather than written as literals, so that this file —
/// which `tracked_sources_carry_no_personal_data` also scans — does not
/// contain the very markers it searches for.
fn presign_markers() -> [String; 3] {
    [
        format!("X-Amz{}", "-Signature"),
        format!("X-Amz{}", "-Credential"),
        format!("amazonaws{}", ".com"),
    ]
}

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

// ----------------------------------------------------------------- accounts

#[test]
fn accounts_carry_the_fields_the_table_reads() {
    let body = fixture("accounts.json");
    let rows = body["accounts"].as_array().expect("accounts array");
    assert!(rows.len() >= 2, "model a checking + savings login");
    for r in rows {
        assert!(r["id"].is_string(), "id is what -a and the BFF key off");
        assert!(r["type"].is_string());
        // Money and APY arrive as strings, never numbers — floats lose cents.
        assert!(r["balance"]["available"].is_string());
        assert!(r["balance"]["ledger"].is_string());
        // LIVE-VERIFIED 2026-08-24: the APY is a string that INCLUDES the
        // trailing percent sign (e.g. "3.10%", "0.50%") — the CLI passes it
        // through verbatim, so a parser that stripped or reformatted `%` would
        // misreport it. Pinned so the spelling can't drift.
        let apy = r["formattedApy"]
            .as_str()
            .expect("formattedApy is a string");
        assert!(
            apy.ends_with('%'),
            "APY keeps its trailing percent: {apy:?}"
        );
        // The interest figures the YTD command reads.
        assert!(r["estimatedInterestThisYear"].is_string());
        assert!(r["interestEarnedLifetime"].is_string());
        assert!(r["status"].is_string());
    }
    // Both account types are present, and map to the family vocabulary. The
    // live login (2026-08-24) showed savings "3.10%" and checking "0.50%".
    let types: Vec<&str> = rows.iter().map(|r| r["type"].as_str().unwrap()).collect();
    assert!(types.contains(&"CHECKING"));
    assert!(types.contains(&"SAVING"), "types: {types:?}");
}

// ------------------------------------------------------------- transactions

#[test]
fn transactions_carry_the_fields_the_ledger_reads() {
    let entries = tx_entries("transactions.json");
    for e in &entries {
        let tx = &e["transaction"];
        assert!(tx["id"].is_string());
        // Amount nests under `unformatted`; the date under `mmddyyyy`, which
        // is UNSEPARATED on the wire (MMDDYYYY — docs/api.md §3.4).
        assert!(tx["amount"]["unformatted"].is_string());
        let date = tx["createdDate"]["mmddyyyy"].as_str().expect("mmddyyyy");
        assert_eq!(date.len(), 8, "MMDDYYYY is 8 digits: {date}");
        assert!(date.bytes().all(|b| b.is_ascii_digit()), "{date}");
        assert!(tx["expandedFields"].is_array());
        assert!(tx["description"].is_string());
        assert!(tx["state"].is_string());
        // The paging cursor lives on the list entry, not the transaction.
        assert!(e["cursor"].is_string());
    }
}

/// A pending row must be present, so the "only POSTED is settled" filter is
/// actually exercised by the fixture.
#[test]
fn a_pending_transaction_is_present_to_exercise_the_filter() {
    let entries = tx_entries("transactions.json");
    let states: Vec<&str> = entries
        .iter()
        .map(|e| e["transaction"]["state"].as_str().unwrap())
        .collect();
    assert!(states.contains(&"POSTED"), "states: {states:?}");
    assert!(states.contains(&"PENDING"), "states: {states:?}");
}

/// The interest fixture carries the `displayType` the heuristic keys off.
#[test]
fn interest_transactions_are_marked_as_interest() {
    let entries = tx_entries("interest_transactions.json");
    assert!(!entries.is_empty());
    for e in &entries {
        let tx = &e["transaction"];
        assert_eq!(tx["displayType"], "INTEREST");
        assert_eq!(tx["state"], "POSTED");
        assert!(tx["amount"]["unformatted"].is_string());
    }
}

fn tx_entries(name: &str) -> Vec<Value> {
    fixture(name)["data"]["me"]["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .flat_map(|a| {
            a["transactions"]["list"]
                .as_array()
                .expect("list array")
                .clone()
        })
        .collect()
}

// --------------------------------------------------------------- statements

#[test]
fn statements_carry_the_fields_the_downloader_needs() {
    let rows = fixture("statements.json");
    let rows = rows.as_array().expect("statements is a bare array");
    assert!(!rows.is_empty());
    for r in rows {
        assert!(
            r["documentId"].is_string(),
            "documentId is the download key"
        );
        let date = r["statementDate"].as_str().expect("statementDate");
        assert_eq!(date.len(), 10, "statementDate is a bare ISO date");
        // Statements are combined across accounts — accountNumber is null.
        assert!(r["accountNumber"].is_null());
        assert!(r["description"].is_string());
    }
}

// --------------------------------------------------------------- auth flow

#[test]
fn an_mfa_challenge_carries_a_token_to_park() {
    let v = fixture("login_mfa_required.json");
    // interpret_login recognizes any of these markers.
    assert!(
        v["mfaRequired"].as_bool() == Some(true)
            || v["status"] == "MFA_REQUIRED"
            || v["mfaToken"].is_string()
    );
    assert!(v["mfaToken"].is_string(), "a token to bind the code to");
}

#[test]
fn a_login_error_body_names_the_failure() {
    let v = fixture("login_error.json");
    assert!(v["error"].is_string());
    assert!(v["message"].is_string());
}

/// A GraphQL error is a 200 carrying an `errors` array; the auth-expiry case
/// names the session, which the client maps to an auth failure not an upstream
/// one.
#[test]
fn a_graphql_error_is_an_errors_array() {
    let v = fixture("graphql_error.json");
    let errors = v["errors"].as_array().expect("errors array");
    assert!(!errors.is_empty());
    assert!(errors[0]["message"].is_string());
    assert!(v["data"].is_null());
}

// ------------------------------------------------------- the scrubbing rails

fn all_fixtures() -> Vec<(String, Value)> {
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixtures dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let raw = std::fs::read_to_string(&path).expect("read fixture");
        let v = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {name}: {e}"));
        out.push((name, v));
    }
    assert!(
        !out.is_empty(),
        "no fixtures found — the scrub check is vacuous"
    );
    out
}

/// The value policy from `tests/fixtures/README.md`.
///
/// Stated positively — "identity-bearing fields must hold a known dummy" —
/// rather than as a denylist of real values, because a denylist would itself
/// publish the values it exists to keep out of the repo.
#[test]
fn fixtures_carry_only_synthetic_identifiers() {
    for (name, value) in all_fixtures() {
        check(&value, None, &name);
    }
}

fn check(v: &Value, key: Option<&str>, path: &str) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                check(val, Some(k), path);
            }
        }
        Value::Array(items) => {
            for item in items {
                check(item, key, path);
            }
        }
        Value::String(s) => {
            let ok = match key {
                Some("email") => s == "user@example.com",
                Some("nickname") | Some("firstName") | Some("lastName") => {
                    s.starts_with("Sample") || s.starts_with("Test")
                }
                // A transaction/statement description is either an obvious
                // dummy merchant (`Sample …`) or a generic, non-identifying
                // provider label the parser depends on.
                Some("description") => {
                    s.starts_with("Sample")
                        || s.starts_with("Test")
                        || s.contains("Statement")
                        || s == "Interest earned"
                }
                // A masked account number is already safe; require the mask.
                Some("number") => s.starts_with("****"),
                Some("mfaToken") => s.starts_with("00000000-"),
                _ => true,
            };
            assert!(
                ok,
                "{path}: key `{}` holds a non-synthetic value {s:?} — see \
                 tests/fixtures/README.md",
                key.unwrap_or("?")
            );

            // Any UUID-shaped string anywhere must be a dummy.
            assert!(
                !looks_like_uuid(s) || is_dummy_uuid(s),
                "{path}: key `{}` holds a real-looking UUID {s:?}",
                key.unwrap_or("?")
            );

            // A phone number must be an obvious dummy (all zeros).
            assert!(
                !has_phone_shape(s) || s.chars().filter(|c| c.is_ascii_digit()).all(|c| c == '0'),
                "{path}: key `{}` holds a real-looking phone number {s:?}",
                key.unwrap_or("?")
            );

            // No pre-sign material anywhere, under any key.
            for marker in presign_markers() {
                assert!(
                    !s.contains(&marker),
                    "{path}: value contains {marker:?} — never commit a pre-signed URL"
                );
            }
        }
        _ => {}
    }
}

fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36
        && s.as_bytes()[8] == b'-'
        && s.as_bytes()[13] == b'-'
        && s.as_bytes()[18] == b'-'
        && s.as_bytes()[23] == b'-'
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// A dummy UUID is nearly all zeros — at most a few significant digits.
fn is_dummy_uuid(s: &str) -> bool {
    s.chars().filter(|c| *c != '-' && *c != '0').count() <= 4
}

/// The scrub check has to be able to fail, or it proves nothing.
#[test]
fn the_dummy_uuid_rule_rejects_a_real_looking_uuid() {
    assert!(looks_like_uuid("00000000-0000-4000-8000-000000000001"));
    assert!(is_dummy_uuid("00000000-0000-4000-8000-000000000001"));

    assert!(looks_like_uuid("58542935-67b5-56e1-a3f9-42686e07fa40"));
    assert!(!is_dummy_uuid("58542935-67b5-56e1-a3f9-42686e07fa40"));

    assert!(!looks_like_uuid("not-a-uuid"));
}

/// The fixture check only ever guarded `tests/fixtures/`. Personal data leaks
/// into prose and examples at least as easily — a phone number in a doc
/// comment, an account number in a README example — so scan the tracked
/// sources too.
#[test]
fn tracked_sources_carry_no_personal_data() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["ls-files"])
        .output();
    let Ok(out) = out else {
        return; // not a git checkout — nothing to scan
    };
    if !out.status.success() {
        return;
    }

    let files = String::from_utf8_lossy(&out.stdout);
    let markers = presign_markers();
    let mut scanned = 0usize;
    for rel in files.lines() {
        if rel.starts_with("tests/fixtures/") || rel.ends_with(".lock") {
            continue;
        }
        let path = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;

        for (n, line) in text.lines().enumerate() {
            assert!(
                !has_phone_shape(line),
                "{rel}:{}: looks like a real phone number",
                n + 1
            );
            for marker in &markers {
                assert!(!line.contains(marker), "{rel}:{}: {marker}", n + 1);
            }
        }
    }
    assert!(scanned > 0, "scanned nothing — the check would be vacuous");
}

/// `NNN-NNN-NNNN` / `(NNN) NNN-NNNN`, ignoring version-like and date-like runs.
fn has_phone_shape(line: &str) -> bool {
    let s: String = line
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    for part in s.split(|c: char| !c.is_ascii_digit() && c != '-') {
        let groups: Vec<&str> = part.split('-').collect();
        if groups.len() == 3 && groups[0].len() == 3 && groups[1].len() == 3 && groups[2].len() == 4
        {
            return true;
        }
    }
    false
}

#[test]
fn the_phone_shape_rule_can_fail() {
    let sample = format!("call {}-{}-{} now", "555", "867", "5309");
    assert!(has_phone_shape(&sample));

    assert!(!has_phone_shape("version 1.431.4"));
    assert!(!has_phone_shape("2026-08-21"));
    assert!(!has_phone_shape("00000000-0000-4000-8000-000000000001"));
}
