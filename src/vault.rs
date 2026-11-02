//! Signing in and opening the vault: with the account on this machine
//! (master password) or with a service account token
//! (`PASSBOX_SERVICE_ACCOUNT_TOKEN`).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use passbox_client::agent::Backend;
use passbox_client::{
    Client, Connectivity, Error, FileStore, Item, ItemData, ServiceAccountClient, Store, Vault,
};
use passbox_core::agent_grant::{Decision, PrincipalKind};
use serde_json::Value;

use crate::login;

pub const TOKEN_ENV: &str = "PASSBOX_SERVICE_ACCOUNT_TOKEN";

pub fn data_dir(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match dir {
        Some(dir) => Ok(dir),
        None => Ok(dirs::data_local_dir()
            .context("no data directory on this system; pass --data-dir")?
            .join("passbox")
            .join("cli")),
    }
}

/// A client that shows up as this machine in the account's device list.
pub fn client(server_url: &str, store: Arc<dyn Store>) -> Client {
    let client = Client::new(server_url, store);
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
    client.set_device(format!("pbx {host}").trim_end(), "cli");
    client
}

pub fn store(dir: Option<PathBuf>) -> anyhow::Result<Arc<dyn Store>> {
    Ok(Arc::new(FileStore::new(data_dir(dir)?)?))
}

/// How secrets may be asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompts {
    /// Ask on the terminal when environment variables are missing.
    Allowed,
    /// Never read from the terminal (`pbx mcp`, whose standard input is the
    /// agent's protocol stream).
    Never,
}

fn password(prompt: &str, prompts: Prompts) -> anyhow::Result<String> {
    match std::env::var("PASSBOX_PASSWORD") {
        Ok(value) if !value.is_empty() => Ok(value),
        _ if prompts == Prompts::Never => bail!(
            "set {TOKEN_ENV} (recommended) or PASSBOX_PASSWORD; pbx mcp cannot ask for a password"
        ),
        _ if !login::can_prompt() => Err(login::headless_error(
            "the master password is needed (or PASSBOX_PASSWORD)",
        )),
        _ => rpassword::prompt_password(prompt).context("could not read the password"),
    }
}

/// Finishes a sign-in or unlock that needs a second factor: reads a code
/// from `PASSBOX_TWO_FACTOR_CODE` or prompts for it (three tries). A code
/// that looks like a recovery code is sent as one. The device is
/// remembered for 30 days unless `PASSBOX_REMEMBER_DEVICE=0`, because every
/// `pbx` command signs in again.
fn second_factor<T>(
    client: &Client,
    result: Result<T, Error>,
    prompts: Prompts,
) -> anyhow::Result<T>
where
    T: Default,
{
    let methods = match result {
        Err(Error::TwoFactorRequired { methods }) => methods,
        other => return Ok(other?),
    };
    if !methods.iter().any(|m| m == "totp" || m == "recovery") {
        bail!(
            "this account only has security keys; sign in once in the web app and use a recovery code here"
        );
    }
    let remember = std::env::var("PASSBOX_REMEMBER_DEVICE").map_or(true, |v| v != "0");
    let from_env = std::env::var("PASSBOX_TWO_FACTOR_CODE")
        .ok()
        .filter(|c| !c.is_empty());
    if from_env.is_none() && prompts == Prompts::Never {
        bail!("this machine needs a two-factor code; run any pbx command in a terminal once first");
    }
    if from_env.is_none() && !login::can_prompt() {
        return Err(login::headless_error(
            "this machine needs a two-factor code (or PASSBOX_TWO_FACTOR_CODE)",
        ));
    }
    for attempt in 0..3 {
        let code = match &from_env {
            Some(code) => code.clone(),
            None => rpassword::prompt_password("Two-factor code (or recovery code): ")
                .context("could not read the code")?,
        };
        let method = if passbox_core::two_factor::looks_like_recovery_code(&code) {
            "recovery"
        } else {
            "totp"
        };
        match client.complete_two_factor(method, &code, remember) {
            Ok(remaining) => {
                if let Some(remaining) = remaining {
                    eprintln!("pbx: recovery code used; {remaining} left");
                }
                return Ok(T::default());
            }
            Err(Error::InvalidTwoFactorCode) if from_env.is_none() && attempt < 2 => {
                eprintln!("pbx: wrong code, try again");
            }
            Err(e) => return Err(e.into()),
        }
    }
    bail!("wrong two-factor code")
}

/// Opens and unlocks the account on this machine.
pub fn unlocked(dir: Option<PathBuf>, prompts: Prompts) -> anyhow::Result<Client> {
    let store = store(dir)?;
    let probe = Client::new("http://localhost", store.clone());
    let account = probe
        .device_account()?
        .ok_or_else(|| anyhow!("not signed in; run `pbx login` first or set {TOKEN_ENV}"))?;
    let client = client(&account.server_url, store);
    let result = client.unlock(&password("Master password: ", prompts)?);
    let connectivity = match result {
        Err(Error::TwoFactorRequired { .. }) => {
            second_factor(&client, result.map(drop), prompts)?;
            Connectivity::Online
        }
        other => other?,
    };
    if connectivity == Connectivity::Offline {
        eprintln!("pbx: server not reachable, using the offline copy");
    }
    Ok(client)
}

/// `pbx login --email`: signs in with the Secret Key typed or passed in,
/// without a browser.
pub fn signin(
    dir: Option<PathBuf>,
    server: &str,
    email: &str,
    secret_key: Option<String>,
) -> anyhow::Result<()> {
    let server = server.trim().trim_end_matches('/');
    let client = client(server, store(dir)?);
    let secret_key = match secret_key {
        Some(key) => key,
        None if !login::can_prompt() => {
            return Err(login::headless_error(
                "the Secret Key is needed (--secret-key or PASSBOX_SECRET_KEY)",
            ));
        }
        None => {
            rpassword::prompt_password("Secret Key: ").context("could not read the Secret Key")?
        }
    };
    let result = client.sign_in(
        email,
        &password("Master password: ", Prompts::Allowed)?,
        &secret_key,
    );
    second_factor(&client, result, Prompts::Allowed)?;
    signed_in(&client, server, email)
}

/// After the browser approved: asks for the master password (three tries
/// when typed, since the approval cannot be used again) and signs in.
pub fn finish_browser_signin(
    client: &Client,
    server: &str,
    email: &str,
    secret_key: &str,
) -> anyhow::Result<()> {
    let from_env = std::env::var("PASSBOX_PASSWORD").is_ok_and(|v| !v.is_empty());
    let mut attempt = 0;
    loop {
        attempt += 1;
        let result = client.sign_in(
            email,
            &password("Master password: ", Prompts::Allowed)?,
            secret_key,
        );
        match result {
            Err(Error::InvalidCredentials) if !from_env && attempt < 3 => {
                eprintln!("pbx: wrong master password, try again");
            }
            other => {
                second_factor(client, other, Prompts::Allowed)?;
                return signed_in(client, server, email);
            }
        }
    }
}

fn signed_in(client: &Client, server: &str, email: &str) -> anyhow::Result<()> {
    let items = client.items()?.len();
    let vaults: Vec<String> = client.vaults()?.into_iter().map(|v| v.name).collect();
    client.lock();
    eprintln!("✓ Signed in as {email} on {server} ({items} items).");
    if !vaults.is_empty() {
        eprintln!("  Vaults: {}", vaults.join(", "));
    }
    eprintln!("  Try `pbx list`, or `pbx --help` for all commands.");
    Ok(())
}

pub fn signout(dir: Option<PathBuf>) -> anyhow::Result<()> {
    Client::new("http://localhost", store(dir)?).sign_out()?;
    eprintln!("Signed out. The account and its offline copy were removed from this machine.");
    Ok(())
}

pub fn status(dir: Option<PathBuf>, json: bool) -> anyhow::Result<()> {
    let account = Client::new("http://localhost", store(dir)?).device_account()?;
    let token = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|t| !t.trim().is_empty());
    if json {
        let value = serde_json::json!({
            "signedIn": account.is_some(),
            "email": account.as_ref().map(|a| a.email.as_str()),
            "server": account.as_ref().map(|a| a.server_url.as_str()),
            // pbx keeps no unlocked state between commands.
            "locked": account.is_some(),
            "serviceAccount": token.as_deref().and_then(|t| passbox_core::service_account::Token::parse(t).ok()).map(|t| t.id().to_owned()),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    if let Some(token) = token {
        match passbox_core::service_account::Token::parse(&token) {
            Ok(t) => println!("Service account {} ({TOKEN_ENV})", t.id()),
            Err(_) => println!("{TOKEN_ENV} is set but is not a service account token"),
        }
    }
    match account {
        Some(account) => {
            println!("Signed in as {} on {}", account.email, account.server_url);
            println!(
                "Vaults are locked: every command unlocks them with the master password \
                 (prompted for, or PASSBOX_PASSWORD)."
            );
        }
        None => println!("Not signed in."),
    }
    Ok(())
}

/// `pbx` without a command.
pub fn overview(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let signed_in = Client::new("http://localhost", store(dir.clone())?)
        .device_account()?
        .is_some();
    let token = std::env::var(TOKEN_ENV).is_ok_and(|t| !t.trim().is_empty());
    if !signed_in && !token && login::interactive() {
        let server = std::env::var("PASSBOX_SERVER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| login::DEFAULT_SERVER.to_owned());
        return login::offer(dir, &server);
    }
    status(dir, false)?;
    if signed_in || token {
        println!();
        println!("  pbx list                    list items");
        println!("  pbx get <item> --field <f>  print a field");
        println!("  pbx run -- <command>        run a command with secrets from pbx:// references");
        println!("  pbx --help                  all commands");
    } else {
        println!();
        println!("Sign in with `pbx login` in a terminal.");
        println!(
            "For CI and scripts, set {TOKEN_ENV} (and PASSBOX_SERVER); see \
             https://github.com/passboxnet/cli/blob/main/docs/cli.md#ci-and-headless"
        );
        println!("Run `pbx --help` for all commands.");
    }
    Ok(())
}

/// The vault access a command works with.
pub enum Session {
    Account(Box<Client>),
    Service(Box<ServiceAccountClient>),
}

impl Session {
    /// Uses `PASSBOX_SERVICE_ACCOUNT_TOKEN` when it is set (with
    /// `PASSBOX_SERVER`, or the server of the account on this machine), the
    /// account on this machine otherwise.
    pub fn open(dir: Option<PathBuf>, prompts: Prompts) -> anyhow::Result<Self> {
        let Some(token) = std::env::var(TOKEN_ENV)
            .ok()
            .filter(|t| !t.trim().is_empty())
        else {
            return Ok(Self::Account(Box::new(unlocked(dir, prompts)?)));
        };
        let server = match std::env::var("PASSBOX_SERVER")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(server) => server,
            None => Client::new("http://localhost", store(dir)?)
                .device_account()?
                .map(|a| a.server_url)
                .ok_or_else(|| {
                    anyhow!(
                        "set PASSBOX_SERVER to the server of the service account \
                         (https://app.passbox.net for the Passbox cloud)"
                    )
                })?,
        };
        let client = ServiceAccountClient::connect(&server, &token)
            .context("could not use the service account")?;
        for problem in client.errors()? {
            eprintln!("pbx: {problem}");
        }
        Ok(Self::Service(Box::new(client)))
    }

    pub fn vault_list(&self) -> anyhow::Result<Vec<Vault>> {
        Ok(Backend::vaults(self)?.into_iter().map(|(v, _)| v).collect())
    }

    pub fn item(&self, id: &str) -> anyhow::Result<Item> {
        Ok(match self {
            Self::Account(c) => c.item(id)?,
            Self::Service(c) => c.item(id)?,
        })
    }

    pub fn update_item(&self, id: &str, data: &ItemData) -> anyhow::Result<()> {
        match self {
            Self::Account(c) => c.update_item(id, data)?,
            Self::Service(c) => c.update_item(id, data)?,
        }
        Ok(())
    }

    pub fn trash_item(&self, id: &str) -> anyhow::Result<()> {
        match self {
            Self::Account(c) => c.trash_item(id)?,
            Self::Service(c) => c.trash_item(id)?,
        }
        Ok(())
    }

    pub fn delete_item(&self, id: &str) -> anyhow::Result<()> {
        match self {
            Self::Account(c) => c.delete_item(id)?,
            Self::Service(c) => c.delete_item(id)?,
        }
        Ok(())
    }

    /// Locks the account (service accounts keep nothing on disk).
    pub fn close(self) {
        if let Self::Account(client) = self {
            client.lock();
        }
    }
}

impl Backend for Session {
    fn principal(&self) -> passbox_client::Result<(PrincipalKind, String, String)> {
        match self {
            Self::Account(c) => c.principal(),
            Self::Service(c) => c.principal(),
        }
    }

    fn vaults(&self) -> passbox_client::Result<Vec<(Vault, bool)>> {
        match self {
            Self::Account(c) => Backend::vaults(&**c),
            Self::Service(c) => Backend::vaults(&**c),
        }
    }

    fn items(&self) -> passbox_client::Result<Vec<Item>> {
        match self {
            Self::Account(c) => c.items(),
            Self::Service(c) => c.items(),
        }
    }

    fn create_item(&self, vault_id: &str, data: &ItemData) -> passbox_client::Result<String> {
        match self {
            Self::Account(c) => c.create_item(vault_id, data),
            Self::Service(c) => c.create_item(vault_id, data),
        }
    }

    fn refresh(&self) -> passbox_client::Result<()> {
        match self {
            Self::Account(c) => c.sync(),
            Self::Service(c) => c.refresh(),
        }
    }

    fn agent_call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> passbox_client::Result<Value> {
        match self {
            Self::Account(c) => c.agent_call(method, path, body),
            Self::Service(c) => c.agent_call(method, path, body),
        }
    }

    fn verify_decision(
        &self,
        request: &[u8],
        decision: &str,
        signature: &str,
    ) -> passbox_client::Result<Decision> {
        match self {
            Self::Account(c) => c.verify_decision(request, decision, signature),
            Self::Service(c) => c.verify_decision(request, decision, signature),
        }
    }

    fn reveal_allowed(&self, vault_id: &str) -> passbox_client::Result<bool> {
        match self {
            Self::Account(c) => c.reveal_allowed(vault_id),
            Self::Service(c) => c.reveal_allowed(vault_id),
        }
    }
}
