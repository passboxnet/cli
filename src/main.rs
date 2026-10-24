//! `pbx`, the Passbox command-line client.
//!
//! Vault commands unlock the account on every call: the master password is
//! read from `PASSBOX_PASSWORD` (for scripts and CI) or prompted for. Data is
//! cached encrypted in the data directory, so reads work offline.

mod vault;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::{Parser, Subcommand};
use passbox_core::generator::{PasswordOptions, generate_password, generate_pin};
use passbox_core::secret_key::SecretKey;
use passbox_core::totp::Totp;

#[derive(Debug, Parser)]
#[command(name = "pbx", version, about = "Passbox command-line client")]
struct Cli {
    /// Directory for the account and the encrypted offline cache.
    #[arg(long, env = "PASSBOX_DATA_DIR", global = true)]
    data_dir: Option<std::path::PathBuf>,

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
    /// Show the account on this machine.
    Status,
    /// List items.
    List {
        /// Only items in this vault (name or ID).
        #[arg(long)]
        vault: Option<String>,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print an item or one of its fields.
    Get {
        /// Item title or ID.
        item: String,
        /// Field ID or label, for example `password`, `username` or `totp`
        /// (prints the current code).
        #[arg(long)]
        field: Option<String>,
        /// Print the item as JSON.
        #[arg(long, conflicts_with = "field")]
        json: bool,
    },
    /// Resolve a secret reference: pbx://<vault>/<item>/<field>.
    Read { reference: String },
    /// Run a command with secret references in environment variables
    /// (values of the form pbx://<vault>/<item>/<field>) replaced by secrets.
    Run {
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
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
    match cli.command {
        Command::Signin {
            server,
            email,
            secret_key,
        } => vault::signin(data_dir, &server, &email, secret_key)?,
        Command::Signout => vault::signout(data_dir)?,
        Command::Status => vault::status(data_dir)?,
        Command::List { vault, json } => vault::list(data_dir, vault.as_deref(), json)?,
        Command::Get { item, field, json } => vault::get(data_dir, &item, field.as_deref(), json)?,
        Command::Read { reference } => vault::read(data_dir, &reference)?,
        Command::Run { command } => std::process::exit(vault::run(data_dir, &command)?),
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
            println!("{value}");
        }
        Command::Totp { secret } => {
            let totp = Totp::parse(&secret)?;
            let now = now()?;
            println!(
                "{}  ({}s remaining)",
                totp.generate(now),
                totp.seconds_remaining(now)
            );
        }
        Command::SecretKey => println!("{}", SecretKey::generate()?.to_display_string()),
    }
    Ok(())
}
