//! Vault commands backed by the Passbox client.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use passbox_client::{Client, Connectivity, FileStore, Item, Store};
use passbox_core::totp::Totp;

const REFERENCE_PREFIX: &str = "pbx://";

fn data_dir(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match dir {
        Some(dir) => Ok(dir),
        None => Ok(dirs::data_local_dir()
            .context("no data directory on this system; pass --data-dir")?
            .join("passbox")
            .join("cli")),
    }
}

fn store(dir: Option<PathBuf>) -> anyhow::Result<Arc<dyn Store>> {
    Ok(Arc::new(FileStore::new(data_dir(dir)?)?))
}

fn password(prompt: &str) -> anyhow::Result<String> {
    match std::env::var("PASSBOX_PASSWORD") {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => rpassword::prompt_password(prompt).context("could not read the password"),
    }
}

/// Opens and unlocks the account on this machine.
fn unlocked(dir: Option<PathBuf>) -> anyhow::Result<Client> {
    let store = store(dir)?;
    let probe = Client::new("http://localhost", store.clone());
    let account = probe
        .device_account()?
        .ok_or_else(|| anyhow!("not signed in; run `pbx signin` first"))?;
    let client = Client::new(&account.server_url, store);
    if client.unlock(&password("Master password: ")?)? == Connectivity::Offline {
        eprintln!("pbx: server not reachable, using the offline copy");
    }
    Ok(client)
}

pub fn signin(
    dir: Option<PathBuf>,
    server: &str,
    email: &str,
    secret_key: Option<String>,
) -> anyhow::Result<()> {
    let client = Client::new(server, store(dir)?);
    let secret_key = match secret_key {
        Some(key) => key,
        None => {
            rpassword::prompt_password("Secret Key: ").context("could not read the Secret Key")?
        }
    };
    client.sign_in(email, &password("Master password: ")?, &secret_key)?;
    let items = client.items()?.len();
    client.lock();
    eprintln!("Signed in as {email} ({items} items).");
    Ok(())
}

pub fn signout(dir: Option<PathBuf>) -> anyhow::Result<()> {
    Client::new("http://localhost", store(dir)?).sign_out()?;
    eprintln!("Signed out. The account and its offline copy were removed from this machine.");
    Ok(())
}

pub fn status(dir: Option<PathBuf>) -> anyhow::Result<()> {
    match Client::new("http://localhost", store(dir)?).device_account()? {
        Some(account) => println!("{} on {}", account.email, account.server_url),
        None => println!("Not signed in."),
    }
    Ok(())
}

pub fn list(dir: Option<PathBuf>, vault: Option<&str>, json: bool) -> anyhow::Result<()> {
    let client = unlocked(dir)?;
    let vaults = client.vaults()?;
    let vault_id = match vault {
        Some(query) => Some(
            vaults
                .iter()
                .find(|v| v.id == query || v.name.eq_ignore_ascii_case(query))
                .map(|v| v.id.clone())
                .ok_or_else(|| anyhow!("no vault named {query:?}"))?,
        ),
        None => None,
    };
    let items: Vec<Item> = client
        .items()?
        .into_iter()
        .filter(|i| vault_id.as_ref().is_none_or(|v| &i.vault_id == v))
        .collect();
    if json {
        let rows: Vec<_> = items
            .iter()
            .map(|i| {
                serde_json::json!({
                    "id": i.id,
                    "title": i.data.title,
                    "category": i.data.category,
                    "vault": vaults.iter().find(|v| v.id == i.vault_id).map(|v| v.name.as_str()),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        for item in items {
            let vault = vaults
                .iter()
                .find(|v| v.id == item.vault_id)
                .map_or("", |v| v.name.as_str());
            println!("{}  {:<32}  {}", item.id, item.data.title, vault);
        }
    }
    client.lock();
    Ok(())
}

/// Finds one item by ID, exact title, or unique title substring.
fn find_item<'a>(items: &'a [Item], query: &str) -> anyhow::Result<&'a Item> {
    if let Some(item) = items.iter().find(|i| i.id == query) {
        return Ok(item);
    }
    let exact: Vec<&Item> = items
        .iter()
        .filter(|i| i.data.title.eq_ignore_ascii_case(query))
        .collect();
    let matches = if exact.is_empty() {
        let q = query.to_lowercase();
        items
            .iter()
            .filter(|i| i.data.title.to_lowercase().contains(&q))
            .collect()
    } else {
        exact
    };
    match matches.as_slice() {
        [item] => Ok(item),
        [] => bail!("no item matches {query:?}"),
        many => bail!(
            "{} items match {query:?}; use the ID: {}",
            many.len(),
            many.iter()
                .map(|i| format!("{} ({})", i.data.title, i.id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Returns a field's value; TOTP fields return the current code.
fn field_value(item: &Item, field: &str) -> anyhow::Result<String> {
    let found = item
        .data
        .fields
        .iter()
        .find(|f| f.id == field || f.label.eq_ignore_ascii_case(field));
    let value = match (field, found) {
        ("notes", None) => return Ok(item.data.notes.clone()),
        (_, Some(f)) if !f.value.is_empty() => f,
        _ => bail!("{:?} has no field {field:?}", item.data.title),
    };
    if value.field_type == passbox_client::FieldType::Totp {
        let totp = if value.value.starts_with("otpauth://") {
            Totp::from_uri(&value.value)?
        } else {
            Totp::from_base32(&value.value)?
        };
        return Ok(totp.generate(crate::now()?));
    }
    Ok(value.value.clone())
}

pub fn get(
    dir: Option<PathBuf>,
    query: &str,
    field: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let client = unlocked(dir)?;
    let items = client.items()?;
    let item = find_item(&items, query)?;
    if let Some(field) = field {
        println!("{}", field_value(item, field)?);
    } else if json {
        println!("{}", serde_json::to_string_pretty(&item.data)?);
    } else {
        println!("{}", item.data.title);
        for field in item.data.fields.iter().filter(|f| !f.value.is_empty()) {
            let shown = match field.field_type {
                passbox_client::FieldType::Concealed => {
                    "••••••••  (use --field to print)".to_owned()
                }
                passbox_client::FieldType::Totp => field_value(item, &field.id)?,
                _ => field.value.clone(),
            };
            println!("  {:<18} {shown}", format!("{}:", field.label));
        }
        if !item.data.notes.is_empty() {
            println!(
                "  {:<18} {}",
                "Notes:",
                item.data.notes.replace('\n', "\n                     ")
            );
        }
    }
    client.lock();
    Ok(())
}

/// Resolves `pbx://<vault>/<item>/<field>`.
fn resolve(client: &Client, reference: &str) -> anyhow::Result<String> {
    let path = reference
        .strip_prefix(REFERENCE_PREFIX)
        .ok_or_else(|| anyhow!("secret references start with {REFERENCE_PREFIX}"))?;
    let parts: Vec<&str> = path.split('/').collect();
    let [vault, item, field] = parts.as_slice() else {
        bail!("secret references look like pbx://<vault>/<item>/<field>");
    };
    let vault_id = client
        .vaults()?
        .into_iter()
        .find(|v| v.id == *vault || v.name.eq_ignore_ascii_case(vault))
        .ok_or_else(|| anyhow!("no vault named {vault:?}"))?
        .id;
    let items: Vec<Item> = client
        .items()?
        .into_iter()
        .filter(|i| i.vault_id == vault_id)
        .collect();
    field_value(find_item(&items, item)?, field)
}

pub fn read(dir: Option<PathBuf>, reference: &str) -> anyhow::Result<()> {
    let client = unlocked(dir)?;
    let value = resolve(&client, reference)?;
    client.lock();
    println!("{value}");
    Ok(())
}

/// Runs a command with resolved secret references. Returns its exit code.
pub fn run(dir: Option<PathBuf>, command: &[String]) -> anyhow::Result<i32> {
    let references: Vec<(String, String)> = std::env::vars()
        .filter(|(_, value)| value.starts_with(REFERENCE_PREFIX))
        .collect();
    let mut resolved = Vec::new();
    if !references.is_empty() {
        let client = unlocked(dir)?;
        for (name, reference) in references {
            let value =
                resolve(&client, &reference).with_context(|| format!("resolving ${name}"))?;
            resolved.push((name, value));
        }
        client.lock();
    }
    let (program, args) = command.split_first().context("no command given")?;
    let status = std::process::Command::new(program)
        .args(args)
        .envs(resolved)
        .env_remove("PASSBOX_PASSWORD")
        .status()
        .with_context(|| format!("could not run {program}"))?;
    Ok(status.code().unwrap_or(1))
}
