//! `sfi` — read-only CLI for SoFi Checking & Savings.
//!
//! Conforms to `piekstra-cli/1` (see `cli-common/DESIGN.md`). This file owns
//! the clap tree and the exit-code mapping; `client.rs` owns HTTP and the
//! login/MFA dance, `config.rs` the non-secret settings, and `commands/*`
//! one module per command group.
//!
//! SoFi publishes no public API for member accounts. Everything here is
//! built against community reverse-engineering and is largely
//! **UNVERIFIED-LIVE** — see `docs/api.md` before trusting an endpoint.

mod browser;
mod client;
mod commands;
mod config;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::{LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_config::ConfigStore;
use pk_cli_core::{output, CliError, CommonArgs, RangeArgs};
use pk_cli_http::ApiArgs;
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};

use crate::config::{Config, BIN, REPO};

/// Read-only access to SoFi Checking & Savings (conforms to piekstra-cli/1).
///
/// Unofficial: SoFi publishes no public member API. See docs/api.md.
#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    /// Account id to act on (checking or savings within the login).
    #[arg(
        short = 'a',
        long,
        global = true,
        value_name = "ID",
        env = "SFI_ACCOUNT"
    )]
    account: Option<String>,

    /// Override the config file location.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Credential management and session status.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Non-secret settings.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// The login's bank accounts (checking, savings, vaults).
    #[command(subcommand)]
    Accounts(AccountsCmd),
    /// Cash balances rolled up (net-worth/v1) — the emergency-fund figure.
    ///
    /// One row per account with the provider's own balance, summed into a
    /// household total. An explicit -a/--account (or SFI_ACCOUNT) narrows it
    /// for this invocation; unlike other reads, a persisted default account
    /// is deliberately ignored, so a configured default can never silently
    /// turn the household figure into one account's balance.
    NetWorth,
    /// Interest earned — the 1099-INT raw material.
    #[command(subcommand)]
    Interest(InterestCmd),
    /// Account transactions — the spending/burn-rate raw material.
    #[command(subcommand)]
    Transactions(TransactionsCmd),
    /// Statements and tax forms (documents/v1 profile).
    #[command(subcommand)]
    Documents(DocumentsCmd),
    /// Raw read-only API passthrough (GET only).
    Api(ApiArgs),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// Log in and cache the session (SoFi raises an MFA code on new devices).
    Login(SofiLoginArgs),
    /// Report credential/session state (auth-status/v1).
    Status(StatusArgs),
    /// Clear the cached session; --forget also removes stored credentials.
    Logout(LogoutArgs),
    /// Raw keychain write for rotation / headless setup.
    SetCredential(SetCredentialArgs),
}

/// `auth login`. The **supported** path is `--browser`; the password/`--code`
/// flow is retained but its endpoint is dead-live (docs/api.md §2).
#[derive(clap::Args, Debug)]
struct SofiLoginArgs {
    #[command(flatten)]
    base: LoginArgs,

    /// Open a Chrome window to sign in (password + MFA) and harvest the
    /// session. This is the supported way to log in: SoFi's Auth0 + Cloudflare
    /// front door can't be cleared headlessly (see docs/api.md §2).
    #[arg(long, conflicts_with_all = ["code", "username"])]
    browser: bool,

    /// SoFi username (usually an email address). Remembered in the config.
    #[arg(long, value_name = "EMAIL")]
    username: Option<String>,

    /// Verification code, to resume a login that requested one.
    ///
    /// An MFA code is bound to the login attempt that raised it, so this
    /// resumes the parked attempt rather than starting a fresh one. Retained
    /// for the day a scriptable login endpoint exists; today it is dead-live.
    #[arg(long, value_name = "CODE")]
    code: Option<String>,

    /// Where to ask SoFi to send the verification code, when the provider
    /// offers a choice (unused by `--browser`).
    #[arg(long, value_enum, default_value = "sms")]
    channel: client::Channel,
}

#[derive(clap::Args, Debug)]
struct StatusArgs {
    /// Spend a request confirming the cached session still works.
    #[arg(long)]
    verify: bool,
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Print the resolved config file path.
    Path,
    /// Show the effective configuration.
    Show,
    /// Set a config key (`username` or `account`).
    Set { key: String, value: String },
    /// Remove a config key.
    Unset { key: String },
}

#[derive(Subcommand, Debug)]
enum AccountsCmd {
    /// List every bank account in this login (account-list/v1).
    #[command(visible_alias = "ls")]
    List,
    /// Show one account; defaults to the selected account.
    Get { id: Option<String> },
}

#[derive(Subcommand, Debug)]
enum InterestCmd {
    /// List interest payments in a date range (interest-list/v1).
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Year-to-date interest total (interest-ytd/v1) — the 1099-INT figure.
    Ytd {
        /// Calendar year to total (default: the current year).
        #[arg(long, value_name = "YYYY")]
        year: Option<u16>,
    },
}

#[derive(Subcommand, Debug)]
enum TransactionsCmd {
    /// List transactions in a date range (transaction-list/v1).
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
    },
}

#[derive(Subcommand, Debug)]
enum DocumentsCmd {
    /// List statements and tax forms, newest first (document-list/v1).
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
        /// Only this document category: `statement` or `tax`.
        #[arg(long = "type", value_name = "TYPE")]
        kind: Option<String>,
    },
    /// Download a document to disk (document-download/v1).
    #[command(visible_alias = "get")]
    Download {
        /// Document id. Omit with --all.
        id: Option<String>,
        /// Write to this file, or directory when used with --all. `-` = stdout.
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Download every matching document into the output directory.
        /// Scoped by --type/--since/--until — without any of them this is
        /// every document the login has ever produced.
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        range: RangeArgs,
        /// Only this document category: `statement` or `tax`. Applies to --all.
        #[arg(long = "type", value_name = "TYPE")]
        kind: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        std::process::exit(output::fail(&e, cli.common.json));
    }
}

fn run(cli: &Cli) -> Result<(), CliError> {
    // Commands that need neither config, keychain, nor network are answered
    // first, so `--help`, `completions`, and `info` can never prompt or hang.
    match &cli.command {
        Command::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            return Ok(());
        }
        Command::Info => return commands::misc::info(cli.common.json),
        Command::SelfUpdate(args) => {
            return Updater {
                repo: REPO.into(),
                binary: BIN.into(),
                target: env!("BUILD_TARGET").into(),
                current: env!("CARGO_PKG_VERSION").into(),
            }
            .run(args, cli.common.json, cli.common.quiet)
        }
        _ => {}
    }

    // Everything checkable without config, keychain, or network is checked
    // here, so bad input fails the same way whether or not the machine has
    // credentials — and never reaches the provider (SPEC v1 §1.2).
    validate(&cli.command)?;

    let store = ConfigStore::new(BIN).with_override(cli.config.clone());
    let cfg: Config = store.load()?;

    match &cli.command {
        Command::Config(cmd) => commands::misc::config(&cli.common, &store, cfg, config_op(cmd)),
        Command::Auth(cmd) => auth_cmd(cli, cmd, &store, cfg),
        _ => {
            // Everything below reads the provider, so it needs a session.
            let ctx = commands::Ctx::new(cli.common.clone(), cfg, cli.account.clone())?;
            match &cli.command {
                Command::Accounts(AccountsCmd::List) => commands::accounts::list(&ctx),
                Command::Accounts(AccountsCmd::Get { id }) => {
                    commands::accounts::get(&ctx, id.as_deref())
                }
                // The explicit flag/env only — never the persisted default
                // account, which must not narrow a household figure.
                Command::NetWorth => {
                    commands::networth::show(&ctx, explicit_account(cli.account.as_deref()))
                }
                Command::Interest(InterestCmd::List { range }) => {
                    commands::interest::list(&ctx, range)
                }
                Command::Interest(InterestCmd::Ytd { year }) => {
                    commands::interest::ytd(&ctx, *year)
                }
                Command::Transactions(TransactionsCmd::List { range }) => {
                    commands::transactions::list(&ctx, range)
                }
                Command::Documents(DocumentsCmd::List { range, kind }) => {
                    commands::documents::list(&ctx, range, kind.as_deref())
                }
                Command::Documents(DocumentsCmd::Download {
                    id,
                    output,
                    all,
                    range,
                    kind,
                }) => commands::documents::download(
                    &ctx,
                    id.as_deref(),
                    output.as_deref(),
                    *all,
                    range,
                    kind.as_deref(),
                ),
                Command::Api(args) => commands::api::run(&ctx, args),
                // Handled above.
                Command::Auth(_)
                | Command::Config(_)
                | Command::SelfUpdate(_)
                | Command::Completions { .. }
                | Command::Info => unreachable!("dispatched before session setup"),
            }
        }
    }
}

/// The `-a` flag / `SFI_ACCOUNT` env for **this invocation** — never the
/// config file's persisted default. `net-worth`'s contract is completeness,
/// and a persisted default silently turning the household total into one
/// account's balance is exactly the quiet misreport the honesty rules exist
/// to prevent.
///
/// An empty value is treated as no selection (clap passes `SFI_ACCOUNT=""` /
/// `-a ""` through as `Some("")`), so an empty env var can't collapse the
/// household figure to a not-found error for account `""`.
fn explicit_account(flag: Option<&str>) -> Option<String> {
    flag.filter(|s| !s.is_empty()).map(str::to_string)
}

/// Argument checks that need nothing but the arguments themselves.
///
/// Kept in one place, ahead of any config load, so `sfi transactions list
/// --since 06/30/2026` is a usage error on a machine that has never been
/// configured — and never reaches the keychain or the provider.
fn validate(command: &Command) -> Result<(), CliError> {
    match command {
        Command::Transactions(TransactionsCmd::List { range })
        | Command::Interest(InterestCmd::List { range }) => range.validate(),

        Command::Interest(InterestCmd::Ytd { year }) => match year {
            // A 4-digit calendar year; the provider's history and this
            // binary's own lifetime both fit comfortably inside the bound.
            Some(y) if !(2000..=2100).contains(y) => Err(CliError::Usage(format!(
                "--year {y} is out of range (2000-2100)"
            ))),
            _ => Ok(()),
        },

        Command::Documents(DocumentsCmd::List { range, kind }) => {
            range.validate()?;
            match kind.as_deref() {
                Some(k) => commands::documents::validate_type(k),
                None => Ok(()),
            }
        }

        Command::Api(args) => {
            // Read-only is a safety property of this tool, so the refusal is a
            // usage error (exit 2), not a confirmation prompt (exit 6): there
            // is no --force that would make a write work, and reporting 6
            // would invite a caller to retry as though there were.
            let method = args.method.trim().to_uppercase();
            if method != "GET" {
                return Err(CliError::Usage(format!(
                    "`sfi api` is read-only and accepts GET only (got {method})"
                )));
            }
            Ok(())
        }

        Command::Documents(DocumentsCmd::Download {
            id,
            all,
            range,
            kind,
            ..
        }) => {
            range.validate()?;
            if let Some(k) = kind.as_deref() {
                commands::documents::validate_type(k)?;
            }
            match (id.is_some(), *all) {
                (true, true) => Err(CliError::Usage(
                    "pass either a document id or --all, not both".into(),
                )),
                (false, false) => Err(CliError::Usage(
                    "which document? pass an id, or --all with -o <DIR>".into(),
                )),
                // Filters only make sense for --all; with an id they would
                // quietly do nothing, which is worse than refusing.
                (true, false)
                    if range.since.is_some()
                        || range.until.is_some()
                        || range.limit.is_some()
                        || kind.is_some() =>
                {
                    Err(CliError::Usage(
                        "--type/--since/--until/--limit scope --all; a document id already names \
                         one document"
                            .into(),
                    ))
                }
                _ => Ok(()),
            }
        }

        _ => Ok(()),
    }
}

fn auth_cmd(cli: &Cli, cmd: &AuthCmd, store: &ConfigStore, cfg: Config) -> Result<(), CliError> {
    match cmd {
        AuthCmd::Login(args) => commands::auth::login(
            &cli.common,
            store,
            cfg,
            &commands::auth::LoginInput {
                base: &args.base,
                browser: args.browser,
                username: args.username.as_deref(),
                code: args.code.as_deref(),
                channel: args.channel,
            },
        ),
        AuthCmd::Status(args) => {
            commands::auth::status(&cli.common, &cfg, cli.account.as_deref(), args.verify)
        }
        AuthCmd::Logout(args) => commands::auth::logout(&cli.common, store, args.forget),
        AuthCmd::SetCredential(args) => {
            commands::auth::set_credential(&cli.common, store, cfg, args)
        }
    }
}

/// Translate the clap enum into the command module's own operation type, so
/// `commands::misc` doesn't depend on the clap tree.
fn config_op(cmd: &ConfigCmd) -> commands::misc::ConfigOp<'_> {
    match cmd {
        ConfigCmd::Path => commands::misc::ConfigOp::Path,
        ConfigCmd::Show => commands::misc::ConfigOp::Show,
        ConfigCmd::Set { key, value } => commands::misc::ConfigOp::Set(key, value),
        ConfigCmd::Unset { key } => commands::misc::ConfigOp::Unset(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// clap's own debug assertions catch conflicting shorts (e.g. a
    /// subcommand `-a` shadowing the global `--account`) only when the command
    /// tree is built, so build it.
    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }
}
