//! `info` and `config` — the parts of the standard surface that need neither
//! the provider nor a credential.

use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{output, CliError, CommonArgs};

use crate::config::{Config, BIN, REPO};

/// `sfi info` — machine discovery (`cli-info/v1`).
pub fn info(json_mode: bool) -> Result<(), CliError> {
    let info = CliInfo::new(
        BIN,
        env!("CARGO_PKG_VERSION"),
        &format!("https://github.com/{REPO}"),
        AuthInfo {
            required: true,
            method: "browser-session".into(),
            login_hint: Some(format!("{BIN} auth login --browser")),
        },
        &[
            "accounts",
            "net-worth",
            "interest",
            "transactions",
            "documents",
            "api",
            "mcp",
        ],
    )
    .with_profiles(&[pk_cli_documents::PROFILE]);
    let v = serde_json::to_value(&info).unwrap_or_default();
    if json_mode {
        output::json(&v);
    } else {
        output::render(&v);
    }
    Ok(())
}

/// The `config` subcommand, expressed without clap so this module does not
/// depend on the command tree.
pub enum ConfigOp<'a> {
    Path,
    Show,
    Set(&'a str, &'a str),
    Unset(&'a str),
}

pub fn config(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    op: ConfigOp<'_>,
) -> Result<(), CliError> {
    match op {
        ConfigOp::Path => {
            println!("{}", store.path()?.display());
            Ok(())
        }
        ConfigOp::Show => {
            let v = serde_json::to_value(&cfg).unwrap_or_default();
            if common.json {
                output::json(&v);
            } else {
                output::render(&v);
            }
            Ok(())
        }
        ConfigOp::Set(key, value) => {
            match parse_key(key)? {
                Key::Username => cfg.username = Some(value.to_string()),
                Key::Account => cfg.account = Some(value.to_string()),
            }
            store.save(&cfg)
        }
        ConfigOp::Unset(key) => {
            match parse_key(key)? {
                Key::Username => cfg.username = None,
                Key::Account => cfg.account = None,
            }
            store.save(&cfg)
        }
    }
}

/// A settable config key. Deliberately a closed set: the config file can
/// never grow a field that holds a secret.
#[derive(Debug)]
enum Key {
    Username,
    Account,
}

fn parse_key(key: &str) -> Result<Key, CliError> {
    match key {
        "username" => Ok(Key::Username),
        "account" => Ok(Key::Account),
        other => Err(CliError::Usage(format!(
            "unknown config key `{other}` (known: username, account)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys_parse_and_unknown_ones_name_the_alternatives() {
        assert!(matches!(parse_key("username"), Ok(Key::Username)));
        assert!(matches!(parse_key("account"), Ok(Key::Account)));

        let err = parse_key("nope").unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("username"));

        // Passwords are keychain-only; the config must never accept one.
        let err = parse_key("password").unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn info_declares_the_documents_profile_and_the_spec() {
        let info = CliInfo::new(
            BIN,
            "0.1.0",
            "https://github.com/piekstra/sofi-cli",
            AuthInfo {
                required: true,
                method: "password".into(),
                login_hint: None,
            },
            &["accounts"],
        )
        .with_profiles(&[pk_cli_documents::PROFILE]);
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["schema"], "cli-info/v1");
        assert_eq!(v["spec"], "piekstra-cli/1");
        assert_eq!(v["name"], "sfi");
        assert_eq!(v["profiles"][0], "documents/v1");
    }
}
