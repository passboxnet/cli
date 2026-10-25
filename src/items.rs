//! `pbx item …`: list, show, create, edit and delete items.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};
use passbox_client::agent::Backend;
use passbox_client::reference::{self, find_item, find_vault};
use passbox_client::{FieldType, Item, ItemCategory, ItemData, Vault, field};
use passbox_core::generator::{PasswordOptions, generate_password};
use serde_json::json;

use crate::vault::{Prompts, Session};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Category {
    Login,
    Note,
    Card,
    Identity,
    Environment,
    Other,
}

impl From<Category> for ItemCategory {
    fn from(value: Category) -> Self {
        match value {
            Category::Login => Self::Login,
            Category::Note => Self::Note,
            Category::Card => Self::Card,
            Category::Identity => Self::Identity,
            Category::Environment => Self::Environment,
            Category::Other => Self::Other,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ItemCommand {
    /// List items (titles and IDs, no secrets).
    List(ListArgs),
    /// Show an item, or print one field.
    Get(GetArgs),
    /// Create an item.
    Create(CreateArgs),
    /// Change an item. Only the given values change.
    Edit(EditArgs),
    /// Move an item to the trash (restorable for 30 days), or delete it
    /// permanently with --permanent.
    Delete(DeleteArgs),
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Only items in this vault (name or ID).
    #[arg(long)]
    pub vault: Option<String>,
    /// Only items of this category.
    #[arg(long, value_enum)]
    pub category: Option<Category>,
    /// Only items with this tag.
    #[arg(long)]
    pub tag: Option<String>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Item title or ID.
    pub item: String,
    /// Only look in this vault (name or ID).
    #[arg(long)]
    pub vault: Option<String>,
    /// Field ID or label, for example `password`, `username` or `totp`
    /// (prints the current code).
    #[arg(long)]
    pub field: Option<String>,
}

/// Values shared by `create` and `edit`.
#[derive(Debug, Args)]
pub struct ValueArgs {
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    /// Website.
    #[arg(long)]
    pub url: Option<String>,
    /// Read the password from standard input (keeps it out of the shell
    /// history and the process list).
    #[arg(long, conflicts_with = "generate_password")]
    pub password_stdin: bool,
    /// Generate a password of this many characters (default 24).
    #[arg(long, num_args = 0..=1, default_missing_value = "24", value_name = "LENGTH")]
    pub generate_password: Option<usize>,
    /// Set a field: `LABEL=VALUE`, `LABEL:TYPE=VALUE` (types: text,
    /// concealed, url, email, totp) or `LABEL=-` to read the value from
    /// standard input. Environment items store each variable as a field.
    #[arg(long = "field", value_name = "SPEC")]
    pub fields: Vec<String>,
    #[arg(long)]
    pub notes: Option<String>,
    /// Add a tag (repeatable).
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    #[arg(long)]
    pub favorite: Option<bool>,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Vault name or ID (default: the only writable vault, or "Private").
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long, value_enum, default_value = "login")]
    pub category: Category,
    #[command(flatten)]
    pub values: ValueArgs,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// Item title or ID.
    pub item: String,
    #[arg(long)]
    pub vault: Option<String>,
    #[command(flatten)]
    pub values: ValueArgs,
    /// Remove a field (ID or label; repeatable).
    #[arg(long = "remove-field", value_name = "FIELD")]
    pub remove_fields: Vec<String>,
    /// Remove a tag (repeatable).
    #[arg(long = "remove-tag")]
    pub remove_tags: Vec<String>,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Item title or ID.
    pub item: String,
    #[arg(long)]
    pub vault: Option<String>,
    /// Delete on all devices right away instead of moving to the trash.
    #[arg(long)]
    pub permanent: bool,
    /// Do not ask before deleting permanently.
    #[arg(long, short)]
    pub yes: bool,
}

pub fn run(dir: Option<PathBuf>, command: ItemCommand, json: bool) -> anyhow::Result<()> {
    let session = Session::open(dir, Prompts::Allowed)?;
    let result = match command {
        ItemCommand::List(args) => list(&session, &args, json),
        ItemCommand::Get(args) => get(&session, &args, json),
        ItemCommand::Create(args) => create(&session, args, json),
        ItemCommand::Edit(args) => edit(&session, args, json),
        ItemCommand::Delete(args) => delete(&session, &args, json),
    };
    session.close();
    result
}

fn vault_name(vaults: &[Vault], id: &str) -> String {
    vaults
        .iter()
        .find(|v| v.id == id)
        .map_or_else(String::new, |v| v.name.clone())
}

pub fn list(session: &Session, args: &ListArgs, json: bool) -> anyhow::Result<()> {
    let vaults = session.vault_list()?;
    let vault_id = args
        .vault
        .as_deref()
        .map(|v| find_vault(&vaults, v).map(|v| v.id.clone()))
        .transpose()?;
    let category = args.category.map(ItemCategory::from);
    let items: Vec<Item> = Backend::items(session)?
        .into_iter()
        .filter(|i| vault_id.as_ref().is_none_or(|v| &i.vault_id == v))
        .filter(|i| category.is_none_or(|c| i.data.category == c))
        .filter(|i| {
            args.tag
                .as_ref()
                .is_none_or(|t| i.data.tags.iter().any(|x| x.eq_ignore_ascii_case(t)))
        })
        .collect();
    if json {
        let rows: Vec<_> = items
            .iter()
            .map(|i| {
                json!({
                    "id": i.id,
                    "title": i.data.title,
                    "category": i.data.category_name(),
                    "vault": vault_name(&vaults, &i.vault_id),
                    "vaultId": i.vault_id,
                    "tags": i.data.tags,
                    "favorite": i.data.favorite,
                    "updatedAt": i.updated_at,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        for item in items {
            println!(
                "{}  {:<32}  {}",
                item.id,
                item.data.title,
                vault_name(&vaults, &item.vault_id)
            );
        }
    }
    Ok(())
}

/// Finds an item, optionally within one vault.
fn locate(
    session: &Session,
    query: &str,
    vault: Option<&str>,
) -> anyhow::Result<(Item, Vec<Vault>)> {
    let vaults = session.vault_list()?;
    let items: Vec<Item> = match vault {
        Some(v) => {
            let id = find_vault(&vaults, v)?.id.clone();
            Backend::items(session)?
                .into_iter()
                .filter(|i| i.vault_id == id)
                .collect()
        }
        None => Backend::items(session)?,
    };
    Ok((find_item(&items, query)?.clone(), vaults))
}

pub fn get(session: &Session, args: &GetArgs, json: bool) -> anyhow::Result<()> {
    let (item, vaults) = locate(session, &args.item, args.vault.as_deref())?;
    if let Some(field) = &args.field {
        let value = reference::field_value(&item, field, crate::now()?)?;
        if json {
            println!("{}", json!({ "field": field, "value": value }));
        } else {
            println!("{value}");
        }
        return Ok(());
    }
    if json {
        let mut value = serde_json::to_value(&item.data)?;
        value["id"] = json!(item.id);
        value["vaultId"] = json!(item.vault_id);
        value["vault"] = json!(vault_name(&vaults, &item.vault_id));
        value["revision"] = json!(item.revision);
        value["updatedAt"] = json!(item.updated_at);
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!("{}", item.data.title);
    for field in item.data.fields.iter().filter(|f| !f.value.is_empty()) {
        let shown = match field.field_type {
            FieldType::Concealed => "••••••••  (use --field to print)".to_owned(),
            FieldType::Totp => reference::field_value(&item, &field.id, crate::now()?)?,
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
    Ok(())
}

fn parse_type(name: &str) -> anyhow::Result<FieldType> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "text" => FieldType::Text,
        "concealed" | "password" | "secret" => FieldType::Concealed,
        "url" => FieldType::Url,
        "email" => FieldType::Email,
        "totp" | "otp" => FieldType::Totp,
        other => bail!("unknown field type {other:?} (text, concealed, url, email, totp)"),
    })
}

/// Reads one value from standard input (the whole input without the final
/// line break). Only one value may come from standard input.
fn stdin_value(used: &mut bool) -> anyhow::Result<String> {
    if *used {
        bail!("only one value can be read from standard input");
    }
    *used = true;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("could not read standard input")?;
    Ok(input.trim_end_matches(['\n', '\r']).to_owned())
}

/// A field ID from a label: lowercase letters, digits and underscores.
pub(crate) fn field_id(label: &str) -> String {
    let id: String = label
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if id.trim_matches('_').is_empty() {
        "field".into()
    } else {
        id
    }
}

fn apply(data: &mut ItemData, values: &ValueArgs) -> anyhow::Result<()> {
    let mut stdin_used = false;
    if let Some(title) = &values.title {
        data.title = title.trim().to_owned();
    }
    if let Some(username) = &values.username {
        data.set_field(
            field::USERNAME,
            "Username",
            FieldType::Text,
            username.as_str(),
        );
    }
    if let Some(url) = &values.url {
        data.set_field(field::URL, "Website", FieldType::Url, url.as_str());
    }
    let password = if values.password_stdin {
        Some(stdin_value(&mut stdin_used)?)
    } else if let Some(length) = values.generate_password {
        Some(generate_password(&PasswordOptions {
            length: length.clamp(8, 128),
            ..PasswordOptions::default()
        })?)
    } else {
        None
    };
    if let Some(password) = password {
        data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
    }
    for spec in &values.fields {
        let (key, value) = spec
            .split_once('=')
            .ok_or_else(|| anyhow!("--field needs LABEL=VALUE, got {spec:?}"))?;
        let (label, kind) = match key.rsplit_once(':') {
            Some((label, kind)) => (label.trim(), Some(parse_type(kind)?)),
            None => (key.trim(), None),
        };
        if label.is_empty() {
            bail!("--field needs a label: {spec:?}");
        }
        let value = if value == "-" {
            stdin_value(&mut stdin_used)?
        } else {
            value.to_owned()
        };
        let default_type = if data.category == ItemCategory::Environment {
            FieldType::Concealed
        } else {
            FieldType::Text
        };
        let existing = data
            .fields
            .iter_mut()
            .find(|f| f.id == label || f.label.eq_ignore_ascii_case(label));
        match existing {
            Some(f) => {
                f.value = value;
                if let Some(kind) = kind {
                    f.field_type = kind;
                }
            }
            None => {
                let mut id = field_id(label);
                while data.fields.iter().any(|f| f.id == id) {
                    id.push('_');
                }
                data.set_field(&id, label, kind.unwrap_or(default_type), value);
            }
        }
    }
    if let Some(notes) = &values.notes {
        data.notes = notes.clone();
    }
    for tag in &values.tags {
        if !data.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
            data.tags.push(tag.trim().to_owned());
        }
    }
    if let Some(favorite) = values.favorite {
        data.favorite = favorite;
    }
    Ok(())
}

fn print_written(session: &Session, action: &str, id: &str, json: bool) -> anyhow::Result<()> {
    let item = session.item(id)?;
    let vaults = session.vault_list()?;
    let items = Backend::items(session)?;
    let reference = vaults
        .iter()
        .find(|v| v.id == item.vault_id)
        .map(|v| reference::reference_for(v, &items, &item, None))
        .unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "id": item.id,
                "title": item.data.title,
                "category": item.data.category_name(),
                "vault": vault_name(&vaults, &item.vault_id),
                "vaultId": item.vault_id,
                "revision": item.revision,
                "reference": reference,
            }))?
        );
    } else {
        eprintln!(
            "{action} {:?} in {} ({}).",
            item.data.title,
            vault_name(&vaults, &item.vault_id),
            item.id
        );
        println!("{reference}");
    }
    Ok(())
}

pub(crate) fn default_vault(session: &Session) -> anyhow::Result<Vault> {
    let writable: Vec<Vault> = Backend::vaults(session)?
        .into_iter()
        .filter(|(_, w)| *w)
        .map(|(v, _)| v)
        .collect();
    match writable.as_slice() {
        [only] => Ok(only.clone()),
        [] => bail!("no vault can be written to"),
        many => many
            .iter()
            .find(|v| v.org_id.is_none() && v.name == "Private")
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "choose a vault with --vault: {}",
                    many.iter()
                        .map(|v| v.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }),
    }
}

pub fn create(session: &Session, args: CreateArgs, json: bool) -> anyhow::Result<()> {
    let vault = match &args.vault {
        Some(v) => find_vault(&session.vault_list()?, v)?.clone(),
        None => default_vault(session)?,
    };
    let title = args
        .values
        .title
        .clone()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("--title is required"))?;
    let mut data = ItemData::new(args.category.into(), title);
    apply(&mut data, &args.values)?;
    let id = Backend::create_item(session, &vault.id, &data)?;
    print_written(session, "Created", &id, json)
}

pub fn edit(session: &Session, args: EditArgs, json: bool) -> anyhow::Result<()> {
    let (item, _) = locate(session, &args.item, args.vault.as_deref())?;
    let mut data = item.data.clone();
    apply(&mut data, &args.values)?;
    for name in &args.remove_fields {
        let before = data.fields.len();
        data.fields
            .retain(|f| f.id != *name && !f.label.eq_ignore_ascii_case(name));
        if data.fields.len() == before {
            bail!("{:?} has no field {name:?}", data.title);
        }
    }
    data.tags
        .retain(|t| !args.remove_tags.iter().any(|r| r.eq_ignore_ascii_case(t)));
    if data.title.trim().is_empty() {
        bail!("the title cannot be empty");
    }
    session.update_item(&item.id, &data)?;
    print_written(session, "Saved", &item.id, json)
}

pub fn delete(session: &Session, args: &DeleteArgs, json: bool) -> anyhow::Result<()> {
    let (item, _) = locate(session, &args.item, args.vault.as_deref())?;
    if args.permanent {
        if !args.yes {
            if !std::io::stdin().is_terminal() {
                bail!("deleting permanently cannot be undone; add --yes to confirm");
            }
            eprint!(
                "Delete {:?} permanently on all devices? This cannot be undone. [y/N] ",
                item.data.title
            );
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y" | "yes") {
                bail!("not deleted");
            }
        }
        session.delete_item(&item.id)?;
    } else {
        session.trash_item(&item.id)?;
    }
    if json {
        println!(
            "{}",
            json!({ "id": item.id, "title": item.data.title, "deleted": args.permanent, "trashed": !args.permanent })
        );
    } else if args.permanent {
        eprintln!("Deleted {:?} permanently.", item.data.title);
    } else {
        eprintln!(
            "Moved {:?} to the trash. Restore it in the Passbox app within 30 days.",
            item.data.title
        );
    }
    Ok(())
}
