//! `pbx scan`: finds leaked secrets in files, directories and staged git
//! changes. Rules only, no AI, nothing leaves the machine. With
//! `--fix`, found secrets are stored in Passbox (one environment item per
//! file) and replaced in the file by `pbx://` references.

mod rules;

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, anyhow, bail};
use clap::Args;
use passbox_client::agent::Backend;
use passbox_client::reference::{self, find_vault};
use passbox_client::{FieldType, ItemCategory, ItemData};
use serde_json::json;

use crate::vault::{Prompts, Session};

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or directories (default: the current directory).
    pub paths: Vec<PathBuf>,
    /// Scan the lines added in staged changes (`git diff --cached`), for a
    /// pre-commit hook.
    #[arg(long, conflicts_with = "fix")]
    pub staged: bool,
    /// Store found secrets in Passbox and replace them in the files with
    /// pbx:// references (asks for each one).
    #[arg(long)]
    pub fix: bool,
    /// With --fix: do not ask, fix every secret that can be fixed.
    #[arg(long, short, requires = "fix")]
    pub yes: bool,
    /// With --fix: the vault for the new items (name or ID).
    #[arg(long, requires = "fix")]
    pub vault: Option<String>,
    /// Skip paths with this name or suffix (repeatable), for example
    /// `fixtures` or `.snap`.
    #[arg(long = "exclude", value_name = "NAME")]
    pub excludes: Vec<String>,
}

/// One secret, with where it was found. `secret` is never printed.
#[derive(Debug, Clone)]
pub struct Finding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: &'static str,
    pub description: &'static str,
    pub variable: Option<String>,
    pub fixable: bool,
    start: usize,
    end: usize,
    secret: String,
}

impl Finding {
    /// The first characters and the length, enough to recognize the value.
    pub fn preview(&self) -> String {
        if self.rule == "private-key" {
            return self
                .secret
                .lines()
                .next()
                .unwrap_or("-----BEGIN PRIVATE KEY-----")
                .to_owned();
        }
        let shown: String = self.secret.chars().take(4).collect();
        format!("{shown}… ({} characters)", self.secret.chars().count())
    }
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    "out",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".gradle",
    ".idea",
    "Pods",
    "DerivedData",
    ".turbo",
    ".cache",
    "coverage",
];
const SKIP_FILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.sum",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
    "bun.lockb",
    "flake.lock",
    "Package.resolved",
];
const SKIP_SUFFIXES: &[&str] = &[
    ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".woff", ".woff2", ".ttf", ".otf", ".wasm", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".class", ".jar", ".svg",
];
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

fn excluded(path: &Path, excludes: &[String]) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    SKIP_FILES.contains(&name)
        || SKIP_SUFFIXES.iter().any(|s| name.ends_with(s))
        || excludes.iter().any(|e| {
            path.components()
                .any(|c| c.as_os_str().to_str() == Some(e.as_str()))
                || path.to_string_lossy().ends_with(e.as_str())
        })
}

fn collect_files(path: &Path, excludes: &[String], out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if SKIP_DIRS.contains(&name) || excluded(path, excludes) {
            return Ok(());
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .with_context(|| format!("could not read {}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for entry in entries {
            collect_files(&entry, excludes, out)?;
        }
    } else if meta.is_file() && meta.len() <= MAX_FILE_BYTES && !excluded(path, excludes) {
        out.push(path.to_owned());
    }
    Ok(())
}

/// Text of a file, or `None` for binary files.
fn read_text(path: &Path) -> anyhow::Result<Option<String>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    if bytes.iter().take(8000).any(|b| *b == 0) {
        return Ok(None);
    }
    Ok(String::from_utf8(bytes).ok())
}

fn line_and_column(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let column = before.rfind('\n').map_or(offset, |i| offset - i - 1) + 1;
    (line, column)
}

/// Findings in a text. `lines` maps the text's line numbers to the file's
/// (for diff hunks); `None` means they are the same.
fn scan_text(path: &Path, text: &str, lines: Option<&[usize]>) -> Vec<Finding> {
    rules::scan(text)
        .into_iter()
        .map(|m| {
            let (line, column) = line_and_column(text, m.start);
            let line = lines.and_then(|l| l.get(line - 1).copied()).unwrap_or(line);
            Finding {
                path: path.to_owned(),
                line,
                column,
                rule: m.rule,
                description: m.description,
                variable: m.variable,
                fixable: m.fixable,
                start: m.start,
                end: m.end,
                secret: text[m.start..m.end].to_owned(),
            }
        })
        .collect()
}

pub fn scan_paths(paths: &[PathBuf], excludes: &[String]) -> anyhow::Result<(Vec<Finding>, usize)> {
    let mut files = Vec::new();
    for path in paths {
        collect_files(path, excludes, &mut files)?;
    }
    let mut findings = Vec::new();
    let mut scanned = 0;
    for file in &files {
        if let Some(text) = read_text(file)? {
            scanned += 1;
            findings.extend(scan_text(file, &text, None));
        }
    }
    Ok((findings, scanned))
}

/// Unquotes a path from a diff header (`"b/na\303\257ve"` style quoting is
/// reduced to the plain path; such paths are rare).
fn diff_path(header: &str) -> Option<String> {
    let path = header.trim().trim_matches('"');
    if path == "/dev/null" {
        return None;
    }
    Some(path.strip_prefix("b/").unwrap_or(path).to_owned())
}

/// Added lines of a unified diff with `-U0`, grouped in runs:
/// `(path, text, file line numbers)`.
pub fn added_runs(diff: &str) -> Vec<(String, String, Vec<usize>)> {
    let mut runs: Vec<(String, String, Vec<usize>)> = Vec::new();
    let mut path: Option<String> = None;
    let mut next_line = 0usize;
    let mut in_run = false;
    for line in diff.lines() {
        if let Some(header) = line.strip_prefix("+++ ") {
            path = diff_path(header);
            in_run = false;
        } else if line.starts_with("@@") {
            // @@ -a,b +c,d @@
            next_line = line
                .split_whitespace()
                .find_map(|p| p.strip_prefix('+'))
                .and_then(|p| p.split(',').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
            in_run = false;
        } else if let (Some(added), Some(p)) = (line.strip_prefix('+'), &path) {
            if !in_run {
                runs.push((p.clone(), String::new(), Vec::new()));
                in_run = true;
            }
            if let Some(run) = runs.last_mut() {
                run.1.push_str(added);
                run.1.push('\n');
                run.2.push(next_line);
            }
            next_line += 1;
        } else if line.starts_with('-') || line.starts_with("diff ") || line.starts_with("index ") {
            in_run = false;
        } else if line.starts_with(' ') {
            next_line += 1;
            in_run = false;
        }
    }
    runs
}

fn scan_staged(excludes: &[String]) -> anyhow::Result<(Vec<Finding>, usize)> {
    let output = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--no-color",
            "--no-ext-diff",
            "--unified=0",
            "--diff-filter=ACMR",
        ])
        .output()
        .context("could not run git")?;
    if !output.status.success() {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let diff = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();
    let mut files = std::collections::BTreeSet::new();
    for (path, text, lines) in added_runs(&diff) {
        let path = PathBuf::from(path);
        if excluded(&path, excludes) {
            continue;
        }
        files.insert(path.clone());
        findings.extend(scan_text(&path, &text, Some(&lines)));
    }
    Ok((findings, files.len()))
}

fn print_findings(findings: &[Finding], scanned: usize, json: bool, staged: bool) {
    if json {
        let rows: Vec<_> = findings
            .iter()
            .map(|f| {
                json!({
                    "path": f.path.display().to_string(),
                    "line": f.line,
                    "column": f.column,
                    "rule": f.rule,
                    "description": f.description,
                    "variable": f.variable,
                    "preview": f.preview(),
                    "fixable": f.fixable,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "findings": rows, "filesScanned": scanned }))
                .unwrap_or_default()
        );
        return;
    }
    for f in findings {
        println!(
            "{}:{}:{}  {}  {}{}",
            f.path.display(),
            f.line,
            f.column,
            f.description,
            f.preview(),
            f.variable
                .as_deref()
                .map(|v| format!("  ({v})"))
                .unwrap_or_default()
        );
    }
    let files: std::collections::BTreeSet<_> = findings.iter().map(|f| &f.path).collect();
    if findings.is_empty() {
        eprintln!("No secrets found ({scanned} files scanned).");
    } else {
        eprintln!(
            "{} secret{} found in {} file{} ({scanned} files scanned).",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            files.len(),
            if files.len() == 1 { "" } else { "s" },
        );
        if staged {
            eprintln!(
                "Remove them from the commit, or store them in Passbox: pbx scan --fix <file>. \
                 A false positive? Add `pbx-scan:ignore` to the line."
            );
        } else {
            eprintln!(
                "Store them in Passbox and replace them with references: pbx scan --fix. \
                 A false positive? Add `pbx-scan:ignore` to the line."
            );
        }
    }
}

/// Runs `pbx scan`; returns the exit code (0 nothing found, 1 secrets
/// found and not fixed).
pub fn run(dir: Option<PathBuf>, args: ScanArgs, json: bool) -> anyhow::Result<i32> {
    let paths = if args.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        args.paths.clone()
    };
    let (findings, scanned) = if args.staged {
        if !args.paths.is_empty() {
            bail!(
                "--staged scans the staged changes of the current repository; leave out the paths"
            );
        }
        scan_staged(&args.excludes)?
    } else {
        scan_paths(&paths, &args.excludes)?
    };
    if !args.fix {
        print_findings(&findings, scanned, json, args.staged);
        return Ok(i32::from(!findings.is_empty()));
    }
    fix(dir, &args, findings, scanned, json)
}

/// Environment-style files take a bare reference (`pbx run --env-file`);
/// other files get a `{{ … }}` template marker for `pbx inject`.
fn env_style(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name.starts_with(".env") || name.ends_with(".env") || name == ".envrc"
}

/// A field label from the variable name or the rule (`GITHUB_TOKEN`).
fn label(finding: &Finding) -> String {
    let raw = finding
        .variable
        .clone()
        .unwrap_or_else(|| finding.rule.to_owned());
    let label: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let label = label.trim_matches('_').to_owned();
    if label.is_empty() {
        "SECRET".into()
    } else {
        label
    }
}

enum Answer {
    Yes,
    No,
    All,
    Quit,
}

fn ask(finding: &Finding) -> anyhow::Result<Answer> {
    eprint!(
        "{}:{}  {}  {}\n  Store it in Passbox and replace it with a reference? [y]es, [n]o, [a]ll, [q]uit: ",
        finding.path.display(),
        finding.line,
        finding.description,
        finding.preview()
    );
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "j" | "ja" => Answer::Yes,
        "a" | "all" => Answer::All,
        "q" | "quit" => Answer::Quit,
        _ => Answer::No,
    })
}

fn fix(
    dir: Option<PathBuf>,
    args: &ScanArgs,
    findings: Vec<Finding>,
    scanned: usize,
    json: bool,
) -> anyhow::Result<i32> {
    if findings.is_empty() {
        print_findings(&findings, scanned, json, false);
        return Ok(0);
    }
    if !args.yes && !std::io::stdin().is_terminal() {
        bail!("--fix asks before changing files; add --yes to fix all without asking");
    }
    // Choose.
    let mut chosen: Vec<Finding> = Vec::new();
    let mut remaining = 0usize;
    let mut all = args.yes;
    let mut quit = false;
    for finding in findings {
        if !finding.fixable {
            eprintln!(
                "{}:{}  {}: not changed (store key files with `pbx item create --category other --field 'key:concealed=-' < {}`).",
                finding.path.display(),
                finding.line,
                finding.description,
                finding.path.display()
            );
            remaining += 1;
            continue;
        }
        if quit {
            remaining += 1;
            continue;
        }
        let take = all
            || match ask(&finding)? {
                Answer::Yes => true,
                Answer::No => false,
                Answer::All => {
                    all = true;
                    true
                }
                Answer::Quit => {
                    quit = true;
                    false
                }
            };
        if take {
            chosen.push(finding);
        } else {
            remaining += 1;
        }
    }
    if chosen.is_empty() {
        eprintln!("Nothing changed.");
        return Ok(i32::from(remaining > 0));
    }

    let session = Session::open(dir, Prompts::Allowed)?;
    let result = store_and_rewrite(&session, args, &chosen, json);
    session.close();
    result?;
    eprintln!(
        "Rotate these secrets at their provider: the old values may still be in git history, backups or logs."
    );
    Ok(i32::from(remaining > 0))
}

fn store_and_rewrite(
    session: &Session,
    args: &ScanArgs,
    chosen: &[Finding],
    json: bool,
) -> anyhow::Result<()> {
    let vault = match &args.vault {
        Some(v) => find_vault(&session.vault_list()?, v)?.clone(),
        None => crate::items::default_vault(session)?,
    };
    let mut files: Vec<&Path> = chosen.iter().map(|f| f.path.as_path()).collect();
    files.dedup();
    let mut report = Vec::new();
    for path in files {
        let in_file: Vec<&Finding> = chosen.iter().filter(|f| f.path == path).collect();
        let text =
            read_text(path)?.ok_or_else(|| anyhow!("{} is not a text file", path.display()))?;
        // One field per distinct secret.
        let mut fields: Vec<(String, String)> = Vec::new();
        for f in &in_file {
            if fields.iter().any(|(_, v)| *v == f.secret) {
                continue;
            }
            let mut name = label(f);
            let base = name.clone();
            let mut n = 2;
            while fields.iter().any(|(l, _)| *l == name) {
                name = format!("{base}_{n}");
                n += 1;
            }
            fields.push((name, f.secret.clone()));
        }
        let absolute = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        let title = format!(
            "{}/{}",
            absolute
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("scan"),
            absolute
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
        );
        let mut data = ItemData::new(ItemCategory::Environment, title.clone());
        for (name, value) in &fields {
            data.set_field(
                &crate::items::field_id(name),
                name,
                FieldType::Concealed,
                value.as_str(),
            );
        }
        data.notes = format!("Stored by pbx scan --fix from {}.", absolute.display());
        data.tags.push("pbx-scan".into());
        let id = Backend::create_item(session, &vault.id, &data)?;
        let item = session.item(&id)?;
        let items = Backend::items(session)?;
        let reference_of = |secret: &str| {
            let name = fields
                .iter()
                .find(|(_, v)| v == secret)
                .map(|(l, _)| l.as_str())
                .unwrap_or("SECRET");
            reference::reference_for(&vault, &items, &item, Some(name))
        };
        // Replace from the end so offsets stay valid.
        let mut rewritten = text.clone();
        let mut spans: Vec<&&Finding> = in_file.iter().collect();
        spans.sort_by_key(|f| std::cmp::Reverse(f.start));
        for f in spans {
            if rewritten.get(f.start..f.end) != Some(f.secret.as_str()) {
                bail!(
                    "{} changed while scanning; nothing was replaced. The secrets are stored in {title:?}.",
                    path.display()
                );
            }
            let reference = reference_of(&f.secret);
            let replacement = if env_style(path) {
                reference.clone()
            } else {
                format!("{{{{ {reference} }}}}")
            };
            rewritten.replace_range(f.start..f.end, &replacement);
            report.push(json!({
                "path": path.display().to_string(),
                "line": f.line,
                "rule": f.rule,
                "reference": reference,
            }));
        }
        std::fs::write(path, rewritten).with_context(|| {
            format!(
                "could not write {}; the secrets are stored in {title:?}",
                path.display()
            )
        })?;
        if !json {
            eprintln!(
                "Stored {} secret{} in {title:?} ({}) and replaced {} in {}.",
                fields.len(),
                if fields.len() == 1 { "" } else { "s" },
                vault.name,
                if in_file.len() == 1 { "it" } else { "them" },
                path.display()
            );
            if env_style(path) {
                eprintln!(
                    "  Run your program with: pbx run --env-file {} -- <command>",
                    path.display()
                );
            } else {
                eprintln!(
                    "  The file is now a template. Render it with: pbx inject -i {} -o <output>",
                    path.display()
                );
            }
        }
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "fixed": report })).unwrap_or_default()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_runs_map_line_numbers() {
        let diff = "diff --git a/app.env b/app.env\nindex 1..2 100644\n--- a/app.env\n+++ b/app.env\n@@ -3,0 +4,2 @@\n+A=1\n+B=2\n@@ -10 +12 @@\n-old\n+new\n";
        let runs = added_runs(diff);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0], ("app.env".into(), "A=1\nB=2\n".into(), vec![4, 5]));
        assert_eq!(runs[1].2, vec![12]);
    }

    #[test]
    fn labels_and_previews() {
        let text = "export GITHUB_TOKEN=ghp_a1B2c3D4e5F6a1B2c3D4e5F6a1B2c3D4e5F6\n";
        let found = scan_text(Path::new(".env"), text, None);
        assert_eq!(found.len(), 1);
        assert_eq!(label(&found[0]), "GITHUB_TOKEN");
        assert_eq!(found[0].line, 1);
        assert_eq!(found[0].column, 21);
        assert_eq!(found[0].preview(), "ghp_… (40 characters)");
        assert!(env_style(Path::new("config/.env.local")));
        assert!(!env_style(Path::new("src/config.ts")));
    }
}
