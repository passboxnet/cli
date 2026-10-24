//! Using secrets without copying them around: `pbx read`, `pbx inject`,
//! `pbx run` and `pbx env`.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use passbox_client::agent::{Backend, SCRUBBED_ENV, write_private};
use passbox_client::reference::{self, PREFIX, Reference};
use passbox_client::{Item, ItemCategory};
use serde_json::json;

use crate::vault::{Prompts, Session};

fn resolve(session: &Session, reference: &str) -> anyhow::Result<String> {
    let vaults = session.vault_list()?;
    let items = Backend::items(session)?;
    Ok(reference::resolve(
        &vaults,
        &items,
        reference,
        crate::now()?,
    )?)
}

pub fn read(dir: Option<PathBuf>, reference: &str, json: bool) -> anyhow::Result<()> {
    Reference::parse(reference)?;
    let session = Session::open(dir, Prompts::Allowed)?;
    let value = resolve(&session, reference);
    session.close();
    let value = value?;
    if json {
        println!("{}", json!({ "reference": reference, "value": value }));
    } else {
        println!("{value}");
    }
    Ok(())
}

/// Renders a template; `output` is written with mode 0600.
pub fn inject(
    dir: Option<PathBuf>,
    input: Option<&Path>,
    output: Option<&Path>,
    force: bool,
    json: bool,
) -> anyhow::Result<()> {
    let template = match input {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?,
        None => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("could not read the template from standard input")?;
            text
        }
    };
    if let Some(path) = output
        && path.exists()
        && !force
    {
        bail!("{} exists; add --force to replace it", path.display());
    }
    let references = reference::template_references(&template);
    let session = Session::open(dir, Prompts::Allowed)?;
    let rendered = {
        let vaults = session.vault_list()?;
        let items = Backend::items(&session)?;
        let now = crate::now()?;
        reference::render_template(&template, |r| {
            reference::resolve(&vaults, &items, r, now)
                .map_err(|e| passbox_client::Error::InvalidData(format!("{r}: {e}")))
        })
    };
    session.close();
    let rendered = rendered?;
    match output {
        Some(path) => {
            write_private(path, rendered.as_bytes())
                .with_context(|| format!("could not write {}", path.display()))?;
            if json {
                println!(
                    "{}",
                    json!({ "output": path.display().to_string(), "references": references.len() })
                );
            } else {
                eprintln!(
                    "Wrote {} ({} secret references resolved).",
                    path.display(),
                    references.len()
                );
            }
        }
        None => {
            std::io::stdout().write_all(rendered.as_bytes())?;
        }
    }
    Ok(())
}

/// `KEY=pbx://…` lines of an env file (comments and other values are
/// passed through unchanged).
fn read_env_file(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("{}:{}: expected KEY=VALUE", path.display(), n + 1))?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.push((key.trim().to_owned(), value.to_owned()));
    }
    Ok(out)
}

fn environment_item<'a>(
    session: &Session,
    items: &'a [Item],
    query: &str,
    vault: Option<&str>,
) -> anyhow::Result<&'a Item> {
    let vaults = session.vault_list()?;
    let item = if query.starts_with(PREFIX) {
        reference::resolve_item(&vaults, items, &Reference::parse(query)?)?
    } else {
        let vault_id = vault
            .map(|v| reference::find_vault(&vaults, v).map(|v| v.id.clone()))
            .transpose()?;
        let candidates: Vec<Item> = items
            .iter()
            .filter(|i| i.data.category == ItemCategory::Environment)
            .filter(|i| vault_id.as_ref().is_none_or(|v| &i.vault_id == v))
            .cloned()
            .collect();
        let found = reference::find_item(&candidates, query)?;
        items.iter().find(|i| i.id == found.id).expect("found")
    };
    if item.data.category != ItemCategory::Environment {
        bail!(
            "{:?} is not an environment item (create one with `pbx item create --category environment`)",
            item.data.title
        );
    }
    Ok(item)
}

/// Runs a command with secret references resolved into its environment.
/// Returns its exit code.
pub fn run(
    dir: Option<PathBuf>,
    env_files: &[PathBuf],
    environments: &[String],
    command: &[String],
) -> anyhow::Result<i32> {
    let mut vars: Vec<(String, String)> = std::env::vars()
        .filter(|(_, value)| value.starts_with(PREFIX))
        .collect();
    for file in env_files {
        vars.extend(read_env_file(file)?);
    }
    let needs_vault = !environments.is_empty() || vars.iter().any(|(_, v)| v.starts_with(PREFIX));
    let mut resolved: Vec<(String, String)> = Vec::new();
    if needs_vault {
        let session = Session::open(dir, Prompts::Allowed)?;
        let result = (|| -> anyhow::Result<()> {
            let items = Backend::items(&session)?;
            for query in environments {
                let item = environment_item(&session, &items, query, None)?;
                resolved.extend(item.data.environment_variables());
            }
            for (name, value) in &vars {
                let value = if value.starts_with(PREFIX) {
                    resolve(&session, value).with_context(|| format!("resolving ${name}"))?
                } else {
                    value.clone()
                };
                resolved.retain(|(n, _)| n != name);
                resolved.push((name.clone(), value));
            }
            Ok(())
        })();
        session.close();
        result?;
    }
    spawn(command, &resolved)
}

fn spawn(command: &[String], vars: &[(String, String)]) -> anyhow::Result<i32> {
    let (program, args) = command.split_first().context("no command given")?;
    let mut process = std::process::Command::new(program);
    process.args(args).envs(vars.iter().map(|(k, v)| (k, v)));
    for name in SCRUBBED_ENV {
        process.env_remove(name);
    }
    let status = process
        .status()
        .with_context(|| format!("could not run {program}"))?;
    Ok(status.code().unwrap_or(1))
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum EnvFormat {
    /// `KEY="value"` lines for `.env` files.
    Dotenv,
    /// `export KEY='value'` lines for `eval "$(pbx env …)"`.
    Shell,
    Json,
}

fn dotenv_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('$', "\\$");
    format!("\"{escaped}\"")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Prints an environment item as `.env` content, or runs a command with its
/// variables.
pub fn env(
    dir: Option<PathBuf>,
    item: &str,
    vault: Option<&str>,
    format: EnvFormat,
    json: bool,
    command: &[String],
) -> anyhow::Result<i32> {
    let session = Session::open(dir, Prompts::Allowed)?;
    let vars = (|| -> anyhow::Result<Vec<(String, String)>> {
        let items = Backend::items(&session)?;
        Ok(environment_item(&session, &items, item, vault)?
            .data
            .environment_variables())
    })();
    session.close();
    let vars = vars?;
    if !command.is_empty() {
        return spawn(command, &vars);
    }
    let format = if json { EnvFormat::Json } else { format };
    if std::io::stdout().is_terminal() && !matches!(format, EnvFormat::Json) {
        eprintln!(
            "pbx: printing secrets to the terminal; redirect to a file or use `pbx env {item} -- <command>`"
        );
    }
    let mut out = String::new();
    match format {
        EnvFormat::Dotenv => {
            for (k, v) in &vars {
                out.push_str(&format!("{k}={}\n", dotenv_quote(v)));
            }
        }
        EnvFormat::Shell => {
            for (k, v) in &vars {
                out.push_str(&format!("export {k}={}\n", shell_quote(v)));
            }
        }
        EnvFormat::Json => {
            let map: serde_json::Map<String, serde_json::Value> =
                vars.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            out = format!("{}\n", serde_json::to_string_pretty(&map)?);
        }
    }
    std::io::stdout().write_all(out.as_bytes())?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(dotenv_quote("a\"b$c\nd"), "\"a\\\"b\\$c\\nd\"");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn env_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env.pbx");
        std::fs::write(
            &path,
            "# comment\nexport A=pbx://V/I/f\nB=\"plain value\"\nC='x'\n",
        )
        .unwrap();
        assert_eq!(
            read_env_file(&path).unwrap(),
            [
                ("A".to_owned(), "pbx://V/I/f".to_owned()),
                ("B".to_owned(), "plain value".to_owned()),
                ("C".to_owned(), "x".to_owned()),
            ]
        );
    }
}
