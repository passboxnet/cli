//! Signing in with the browser (`pbx login`), and when `pbx` may talk to a
//! person at all.
//!
//! `pbx login` registers a sign-in request with the server and prints a
//! link to the web vault. The link's secret is in its fragment, which the
//! browser never sends to a server. The signed-in web vault checks the
//! request against the secret and, after the user approves, seals the
//! account's email, ID and Secret Key to a key that only this process has.
//! `pbx` then asks for the master password (never transferred) and signs in
//! like `pbx login --email` does. See passboxnet/core,
//! docs/architecture/recovery.md ("Signing in pbx from the browser").

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use passbox_client::{CliLoginPoll, Client, Error};

use crate::vault;

/// The Passbox cloud; `--server` or `PASSBOX_SERVER` for self-hosted servers.
pub const DEFAULT_SERVER: &str = "https://app.passbox.net";
const DOCS: &str = "https://github.com/passboxnet/cli/blob/main/docs/cli.md#ci-and-headless";
const POLL_EVERY: Duration = Duration::from_secs(2);
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// `CI` is set (GitHub Actions, GitLab CI and most others set `CI=true`).
pub fn in_ci() -> bool {
    std::env::var("CI").is_ok_and(|v| ci_value(&v))
}

fn ci_value(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
}

/// Whether `pbx` may start an interactive sign-in: standard input and output
/// are a terminal and `CI` is not set.
pub fn interactive() -> bool {
    !in_ci() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Whether `pbx` may ask for a password. Prompts are read from the terminal
/// itself, so piping the output (`pbx read … | pbcopy`) still works; in CI or
/// without any terminal they never happen.
pub fn can_prompt() -> bool {
    !in_ci() && (std::io::stdin().is_terminal() || std::io::stderr().is_terminal())
}

/// Why `pbx` will not ask, and what to do instead.
pub fn headless_error(what: &str) -> anyhow::Error {
    let why = if in_ci() {
        "CI is set"
    } else {
        "this is not an interactive terminal"
    };
    anyhow!(
        "{what}, but {why}, so pbx will not prompt or open a browser.\n\
         For CI and scripts, use a service account: set {token} (and PASSBOX_SERVER to your server's URL).\n\
         See {DOCS}",
        token = vault::TOKEN_ENV,
    )
}

/// Ctrl+C while waiting withdraws the request; at any other time it ends
/// `pbx` as usual.
static WAITING: AtomicBool = AtomicBool::new(false);
static CANCELLED: AtomicBool = AtomicBool::new(false);

fn install_ctrl_c() {
    // Fails only if a handler is set already, which pbx never does elsewhere.
    let _ = ctrlc::set_handler(|| {
        if WAITING.load(Ordering::SeqCst) {
            CANCELLED.store(true, Ordering::SeqCst);
        } else {
            std::process::exit(130);
        }
    });
}

/// Over SSH a browser would open on the remote machine (or not at all), so
/// `pbx` only prints the link there.
fn remote_session() -> bool {
    let ssh = ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some());
    let display = cfg!(any(target_os = "macos", windows))
        || ["DISPLAY", "WAYLAND_DISPLAY"]
            .iter()
            .any(|v| std::env::var_os(v).is_some());
    ssh || !display
}

fn wait_for_enter() -> anyhow::Result<()> {
    eprint!("Press Enter to sign in with your browser (or Ctrl+C to cancel)...");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin()
        .read_line(&mut line)
        .context("could not read from the terminal")?;
    if read == 0 {
        bail!("cancelled");
    }
    Ok(())
}

fn clear_line() {
    eprint!("\r\x1b[2K");
}

/// `pbx` without a command on a machine that is not signed in.
pub fn offer(dir: Option<PathBuf>, server: &str) -> anyhow::Result<()> {
    eprintln!("You are not signed in.");
    browser(dir, server, false, Some(true))
}

/// Signs in through a signed-in browser. `ask` waits for Enter first; by
/// default only when a browser is about to open.
pub fn browser(
    dir: Option<PathBuf>,
    server: &str,
    no_browser: bool,
    ask: Option<bool>,
) -> anyhow::Result<()> {
    if !interactive() {
        return Err(headless_error("signing in needs you at the keyboard"));
    }
    let server = server.trim().trim_end_matches('/');
    let open_browser = !no_browser && !remote_session();
    if ask.unwrap_or(open_browser) {
        wait_for_enter()?;
    }
    let client = vault::client(server, vault::store(dir)?);
    let start = client
        .start_cli_login()
        .with_context(|| format!("could not start the sign-in on {server}"))?;
    install_ctrl_c();
    WAITING.store(true, Ordering::SeqCst);

    eprintln!("Open this link in a browser where you are signed in to Passbox:");
    println!("{}", start.url);
    if open_browser && open::that_detached(&start.url).is_err() {
        eprintln!("(Could not open a browser. Open the link yourself.)");
    }

    let outcome = wait(&client, start.expires_at);
    WAITING.store(false, Ordering::SeqCst);
    let (account, approved_by) = outcome?;
    if approved_by.is_empty() {
        eprintln!("✓ {}", account.email);
    } else {
        eprintln!("✓ {} (approved on {approved_by})", account.email);
    }
    vault::finish_browser_signin(&client, server, &account.email, &account.secret_key)
}

/// Polls until the browser answers, the request expires or Ctrl+C.
fn wait(
    client: &Client,
    expires_at: i64,
) -> anyhow::Result<(passbox_client::LinkedAccount, String)> {
    let deadline = Instant::now()
        + Duration::from_millis((expires_at - now_ms()).clamp(60_000, 15 * 60_000) as u64 + 5_000);
    let spinner = std::io::stderr().is_terminal();
    let mut next_poll = Instant::now();
    let mut frame = 0usize;
    loop {
        if CANCELLED.load(Ordering::SeqCst) {
            if spinner {
                clear_line();
            }
            let _ = client.cancel_cli_login();
            eprintln!("Cancelled. The sign-in request was withdrawn.");
            std::process::exit(130);
        }
        let now = Instant::now();
        if now >= deadline {
            let _ = client.cancel_cli_login();
            if spinner {
                clear_line();
            }
            bail!("the sign-in request expired after 10 minutes; run `pbx login` again");
        }
        if now >= next_poll {
            next_poll = now + POLL_EVERY;
            match client.poll_cli_login() {
                Ok(CliLoginPoll::Pending) => {}
                Ok(CliLoginPoll::Approved {
                    account,
                    approved_by,
                }) => {
                    if spinner {
                        clear_line();
                    }
                    eprint!("Waiting for approval... ");
                    return Ok((account, approved_by));
                }
                Ok(CliLoginPoll::Denied) => {
                    if spinner {
                        clear_line();
                    }
                    bail!("the sign-in was denied in the browser");
                }
                Ok(CliLoginPoll::Expired) => {
                    if spinner {
                        clear_line();
                    }
                    bail!("the sign-in request expired or was cancelled; run `pbx login` again");
                }
                // A short network problem or a rate limit: keep waiting.
                Err(Error::Network(_)) | Err(Error::Server { status: 429, .. }) => {}
                Err(Error::Server { status, .. }) if status >= 500 => {}
                Err(e) => {
                    if spinner {
                        clear_line();
                    }
                    return Err(anyhow::Error::new(e).context("waiting for the approval failed"));
                }
            }
        }
        if spinner {
            let left = deadline
                .saturating_duration_since(now)
                .as_secs()
                .saturating_sub(5);
            eprint!(
                "\r{} Waiting for approval... ({}:{:02} left, Ctrl+C to cancel)",
                SPINNER[frame % SPINNER.len()],
                left / 60,
                left % 60
            );
            std::io::stderr().flush().ok();
            frame += 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_values() {
        assert!(ci_value("true") && ci_value("1") && ci_value("yes"));
        assert!(!ci_value("") && !ci_value(" 0") && !ci_value("false") && !ci_value("FALSE"));
    }
}
