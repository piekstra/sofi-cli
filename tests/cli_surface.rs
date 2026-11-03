//! Black-box tests over the built binary. Fully offline: nothing here touches
//! the network, and every test that could reach the keychain is either
//! config-isolated or opt-in.

use std::path::PathBuf;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use predicates::str::contains;

/// Tests that reach the OS keychain are opt-in.
///
/// Two reasons. On macOS, `cargo test` rebuilds an ad-hoc-signed binary each
/// run, which the OS treats as a new code identity — so a keychain read can
/// raise a permission dialog, and a developer who happens to have a real
/// session stored would get a different answer than a clean machine. On Linux
/// CI there is no D-Bus session at all, so the keyring backend errors
/// (exit 1) instead of reporting "no entry" (exit 3). Neither is a bug in the
/// CLI, and neither belongs in an offline gate.
///
/// Run them deliberately with `SFI_TEST_KEYCHAIN=1 cargo test`.
fn keychain_tests_enabled() -> bool {
    std::env::var("SFI_TEST_KEYCHAIN").as_deref() == Ok("1")
}

fn sfi() -> Command {
    Command::cargo_bin("sfi").expect("binary builds")
}

/// A throwaway config path, so a test never reads or writes the developer's
/// real `~/.config/sfi/config.json`.
fn scratch_config(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sfi-test-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join("config.json")
}

/// Run with an isolated config and no ambient account selection, so the
/// developer's environment can't change a test's outcome.
fn isolated(tag: &str) -> Command {
    let mut c = sfi();
    c.arg("--config").arg(scratch_config(tag));
    c.env_remove("SFI_ACCOUNT");
    c
}

const GROUPS: &[&str] = &[
    "auth",
    "config",
    "accounts",
    "net-worth",
    "interest",
    "transactions",
    "documents",
    "api",
    "mcp",
    "self-update",
    "completions",
    "info",
];

#[test]
fn top_level_help_lists_the_surface() {
    let out = sfi().arg("--help").assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for g in GROUPS {
        assert!(text.contains(g), "top-level help is missing `{g}`:\n{text}");
    }
    // The global flags the family spec requires.
    for flag in ["--json", "--verbose", "--quiet", "--no-color", "--account"] {
        assert!(text.contains(flag), "top-level help is missing `{flag}`");
    }
}

/// Rendering a subcommand's help forces clap's debug assertions to run over
/// that subtree, which is what catches conflicting short flags (e.g. a
/// subcommand `-a` colliding with the global `--account`).
#[test]
fn every_subcommand_help_renders() {
    for g in GROUPS {
        sfi().arg(g).arg("--help").assert().success();
    }
}

#[test]
fn nested_subcommand_help_renders() {
    let nested = [
        ["auth", "login"],
        ["auth", "status"],
        ["auth", "logout"],
        ["auth", "set-credential"],
        ["config", "set"],
        ["accounts", "list"],
        ["accounts", "get"],
        ["interest", "list"],
        ["interest", "ytd"],
        ["transactions", "list"],
        ["documents", "list"],
        ["documents", "download"],
    ];
    for pair in nested {
        sfi()
            .args(pair)
            .arg("--help")
            .assert()
            .success()
            .stdout(contains("Usage"));
    }
}

/// The supported login flag is advertised on `auth login --help`.
#[test]
fn auth_login_help_documents_the_browser_flag() {
    sfi()
        .args(["auth", "login", "--help"])
        .assert()
        .success()
        .stdout(contains("--browser"));
}

/// `--fresh-profile` picks the profile a browser sign-in runs in, so alone it
/// would do nothing: a usage error, before any keychain/network/browser work.
#[test]
fn fresh_profile_requires_the_browser_flag() {
    sfi()
        .args(["auth", "login", "--help"])
        .assert()
        .success()
        .stdout(contains("--fresh-profile"));
    isolated("freshalone")
        .args(["auth", "login", "--fresh-profile"])
        .assert()
        .code(2)
        .stderr(contains("--browser"));
}

/// `--browser` harvests a whole session, so it can't be combined with the
/// single-code resume or a username; the conflict is a usage error, caught
/// before any keychain/network/browser work.
#[test]
fn browser_conflicts_with_code_and_username() {
    for extra in [
        vec!["--browser", "--code", "123456"],
        vec!["--browser", "--username", "you@example.com"],
    ] {
        isolated("browserconflict")
            .arg("auth")
            .arg("login")
            .args(extra)
            .assert()
            .code(2);
    }
}

#[test]
fn version_prints_the_crate_version() {
    sfi()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn info_emits_cli_info_dto() {
    let out = sfi().args(["info", "--json"]).assert().success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("info emits JSON");
    assert_eq!(v["schema"], "cli-info/v1");
    assert_eq!(v["spec"], "piekstra-cli/1");
    assert_eq!(v["name"], "sfi");
    assert_eq!(v["auth"]["required"], true);
    // The documents domain profile is what an archiver keys off.
    assert_eq!(v["profiles"][0], "documents/v1");
    let caps = v["capabilities"].as_array().expect("capabilities array");
    for expected in [
        "accounts",
        "net-worth",
        "interest",
        "transactions",
        "documents",
        "api",
        "mcp",
    ] {
        assert!(
            caps.iter().any(|c| c == expected),
            "capabilities missing {expected}"
        );
    }
}

#[test]
fn unknown_command_is_a_usage_error() {
    sfi().arg("nope").assert().code(2);
}

/// Dates are validated before any config load, so this is a usage error even
/// on a machine that has never been configured.
#[test]
fn bad_date_is_a_usage_error() {
    isolated("baddate")
        .args(["transactions", "list", "--since", "06/30/2026"])
        .assert()
        .code(2);
}

#[test]
fn inverted_range_is_a_usage_error() {
    isolated("inverted")
        .args([
            "transactions",
            "list",
            "--since",
            "2026-12-31",
            "--until",
            "2026-01-01",
        ])
        .assert()
        .code(2);
}

#[test]
fn an_out_of_range_ytd_year_is_a_usage_error() {
    isolated("ytdyear")
        .args(["interest", "ytd", "--year", "1999"])
        .assert()
        .code(2);
    // A non-numeric year fails clap's own parse, same exit code.
    isolated("ytdnan")
        .args(["interest", "ytd", "--year", "twenty"])
        .assert()
        .code(2);
}

/// Read-only is a safety property, so a write verb must be refused before the
/// keychain or the network is touched.
#[test]
fn api_refuses_anything_but_get() {
    for method in ["POST", "PUT", "DELETE", "patch"] {
        isolated("apiverb")
            .args(["api", method, "/accounts"])
            .assert()
            .code(2)
            .stderr(contains("read-only"));
    }
}

#[test]
fn api_accepts_get_far_enough_to_need_credentials() {
    if !keychain_tests_enabled() {
        return;
    }
    // No session configured, so this must fail as auth (3) — proving the verb
    // check passed and the failure is about credentials, not usage.
    isolated("apiget")
        .args(["api", "GET", "/accounts"])
        .assert()
        .code(3);
}

#[test]
fn documents_download_requires_a_target() {
    isolated("dltarget")
        .args(["documents", "download"])
        .assert()
        .code(2);
    isolated("dlboth")
        .args(["documents", "download", "abc", "--all"])
        .assert()
        .code(2);
}

/// Filters scope `--all`; with an explicit id they would silently do nothing.
#[test]
fn download_filters_require_all() {
    isolated("dlfilter")
        .args(["documents", "download", "abc", "--type", "statement"])
        .assert()
        .code(2);
}

#[test]
fn json_errors_use_the_family_error_dto() {
    let out = isolated("jsonerr")
        .args(["transactions", "list", "--since", "nope", "--json"])
        .assert()
        .code(2);
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("error DTO on stdout");
    assert_eq!(v["error"]["code"], "usage");
    assert!(v["error"]["message"].is_string());
}

/// With no credentials stored, a read must fail as auth (3) with a message
/// pointing at login — not panic, and not claim an empty account. Includes
/// `net-worth`, which must never report $0 for "not logged in".
#[test]
fn a_read_without_credentials_is_an_auth_error() {
    if !keychain_tests_enabled() {
        return;
    }
    for (tag, args) in [
        ("noauth", &["accounts", "list"][..]),
        ("noauthnw", &["net-worth"][..]),
        ("noauthint", &["interest", "ytd"][..]),
    ] {
        isolated(tag)
            .args(args)
            .assert()
            .code(3)
            .stderr(contains("auth login"));
    }
}

#[test]
fn config_roundtrips_a_key() {
    let cfg = scratch_config("configset");
    let _ = std::fs::remove_file(&cfg);

    sfi()
        .arg("--config")
        .arg(&cfg)
        .args(["config", "set", "account", "1111222233"])
        .assert()
        .success();

    let out = sfi()
        .arg("--config")
        .arg(&cfg)
        .args(["config", "show", "--json"])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("config show emits JSON");
    assert_eq!(v["account"], "1111222233");
}

#[test]
fn config_rejects_a_password_key() {
    // Passwords are keychain-only; the config file must never accept one.
    isolated("configpw")
        .args(["config", "set", "password", "hunter2"])
        .assert()
        .code(2);
}

#[test]
fn completions_generate_for_each_shell() {
    for shell in ["bash", "zsh", "fish"] {
        sfi()
            .args(["completions", shell])
            .assert()
            .success()
            .stdout(predicates::str::is_empty().not());
    }
}

/// no-color.org: any non-empty `NO_COLOR` turns color off. cli-common before
/// v0.15.1 parsed it as a clap bool, so `NO_COLOR=1` failed every command with
/// a usage error.
#[test]
fn no_color_in_the_environment_never_fails_a_command() {
    for v in ["1", "true", "0", ""] {
        isolated("no-color")
            .env("NO_COLOR", v)
            .args(["completions", "bash"])
            .assert()
            .success();
    }
}
