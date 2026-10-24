//! `pbx`, the Passbox command-line client.
//!
//! Vault commands unlock the account on every call: the master password is
//! read from `PASSBOX_PASSWORD` (for scripts and CI) or prompted for. With
//! `PASSBOX_SERVICE_ACCOUNT_TOKEN` set, they use that service account
//! instead. Data is cached encrypted in the data directory, so reads work
//! offline.

mod items;
mod mcp;
mod secrets;
mod vault;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::{CommandFactory, Parser, Subcommand};
use passbox_core::generator::{PasswordOptions, generate_password, generate_pin};
use passbox_core::secret_key::SecretKey;
use passbox_core::totp::Totp;

#[derive(Debug, Parser)]
#[command(name = "pbx", version, about = "Passbox command-line client")]
struct Cli {
    /// Directory for the account and the encrypted offline cache.
    #[arg(long, env = "PASSBOX_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,

    /// Print JSON (every command that prints data supports it).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Sign in to a Passbox server on this machine.
    Signin {
        /// Server URL, for example https://passbox.example.com.
        #[arg(long, env = "PASSBOX_SERVER")]
        server: String,
        #[arg(long, env = "PASSBOX_EMAIL")]
        email: String,
        /// Secret Key from the Emergency Kit (prompted for if omitted).
        #[arg(long, env = "PASSBOX_SECRET_KEY", hide_env_values = true)]
        secret_key: Option<String>,
    },
    /// Remove the account and its cache from this machine.
    Signout,
    /// Show the account (and service account) used on this machine.
    Status,
    /// Create, show, change and delete items.
    #[command(subcommand)]
    Item(items::ItemCommand),
    /// List items (same as `pbx item list`).
    List(items::ListArgs),
    /// Print an item or one of its fields (same as `pbx item get`).
    Get(items::GetArgs),
    /// Resolve a secret reference: pbx://<vault>/<item>/<field>.
    Read { reference: String },
    /// Render a template, replacing {{ pbx://<vault>/<item>/<field> }} with
    /// secrets. The output file is readable only by you.
    Inject {
        /// Template file (default: standard input).
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Output file (default: standard output).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
    },
    /// Run a command with secret references in environment variables
    /// (values of the form pbx://<vault>/<item>/<field>) replaced by secrets.
    Run {
        /// Also read KEY=VALUE lines from this file (values may be
        /// references; repeatable).
        #[arg(long = "env-file")]
        env_files: Vec<PathBuf>,
        /// Add all variables of an environment item (title or
        /// pbx://<vault>/<item>; repeatable).
        #[arg(long = "environment")]
        environments: Vec<String>,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Print an environment item as .env content, or run a command with its
    /// variables: `pbx env API -- npm start`.
    Env {
        /// Environment item title, ID or pbx://<vault>/<item>.
        item: String,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long, value_enum, default_value = "dotenv")]
        format: secrets::EnvFormat,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run the MCP server for AI agents on standard input and output.
    /// Secrets are used only with approval on another device and are never
    /// returned to the agent.
    Mcp,
    /// Generate a password or PIN.
    Generate {
        /// Number of characters.
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        /// Leave out symbols.
        #[arg(long)]
        no_symbols: bool,
        /// Leave out characters that are easy to confuse (l, 1, O, 0, ...).
        #[arg(long)]
        avoid_ambiguous: bool,
        /// Generate a numeric PIN instead of a password.
        #[arg(long, conflicts_with_all = ["no_symbols", "avoid_ambiguous"])]
        pin: bool,
    },
    /// Print the current one-time password for an otpauth:// URI or Base32 secret.
    Totp {
        /// otpauth:// URI or Base32 secret.
        secret: String,
    },
    /// Print shell completions: `pbx completions bash > /etc/bash_completion.d/pbx`.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Generate a new Secret Key (for testing; accounts create their own).
    SecretKey,
}

fn now() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before 1970")?
        .as_secs())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone();
    let json = cli.json;
    match cli.command {
        Command::Signin {
            server,
            email,
            secret_key,
        } => vault::signin(data_dir, &server, &email, secret_key)?,
        Command::Signout => vault::signout(data_dir)?,
        Command::Status => vault::status(data_dir, json)?,
        Command::Item(command) => items::run(data_dir, command, json)?,
        Command::List(args) => items::run(data_dir, items::ItemCommand::List(args), json)?,
        Command::Get(args) => items::run(data_dir, items::ItemCommand::Get(args), json)?,
        Command::Read { reference } => secrets::read(data_dir, &reference, json)?,
        Command::Inject {
            input,
            output,
            force,
        } => secrets::inject(data_dir, input.as_deref(), output.as_deref(), force, json)?,
        Command::Run {
            env_files,
            environments,
            command,
        } => std::process::exit(secrets::run(data_dir, &env_files, &environments, &command)?),
        Command::Env {
            item,
            vault,
            format,
            command,
        } => {
            let code = secrets::env(data_dir, &item, vault.as_deref(), format, json, &command)?;
            if !command.is_empty() {
                std::process::exit(code);
            }
        }
        Command::Mcp => mcp::serve(data_dir)?,
        Command::Generate {
            length,
            no_symbols,
            avoid_ambiguous,
            pin,
        } => {
            let value = if pin {
                generate_pin(length)?
            } else {
                generate_password(&PasswordOptions {
                    length,
                    symbols: !no_symbols,
                    avoid_ambiguous,
                    ..PasswordOptions::default()
                })?
            };
            if json {
                println!("{}", serde_json::json!({ "value": value }));
            } else {
                println!("{value}");
            }
        }
        Command::Totp { secret } => {
            let totp = Totp::parse(&secret)?;
            let now = now()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "code": totp.generate(now), "secondsRemaining": totp.seconds_remaining(now) })
                );
            } else {
                println!(
                    "{}  ({}s remaining)",
                    totp.generate(now),
                    totp.seconds_remaining(now)
                );
            }
        }
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "pbx", &mut std::io::stdout());
        }
        Command::SecretKey => println!("{}", SecretKey::generate()?.to_display_string()),
    }
    Ok(())
}
