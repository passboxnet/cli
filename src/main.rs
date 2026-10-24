//! `pbx`, the Passbox command-line client.
//!
//! Vault access (`pbx get`, `pbx run`, ...) follows once the sync API exists.
//! For now the CLI exposes the offline tools from the core.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::{Parser, Subcommand};
use passbox_core::generator::{PasswordOptions, generate_password, generate_pin};
use passbox_core::secret_key::SecretKey;
use passbox_core::totp::Totp;

#[derive(Debug, Parser)]
#[command(name = "pbx", version, about = "Passbox command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
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
            let totp = if secret.starts_with("otpauth://") {
                Totp::from_uri(&secret)?
            } else {
                Totp::from_base32(&secret)?
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before 1970")?
                .as_secs();
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
