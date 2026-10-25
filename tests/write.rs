//! Writing with `pbx`, templates, environments, service accounts and
//! `pbx mcp`, against an in-process server.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use passbox_client::{Client, FieldType, ItemCategory, ItemData, MemoryStore, field};
use passbox_core::service_account::Permission;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";

fn start_server() -> String {
    passbox_server::testing::spawn_server(|state, _| state.auth_rate_limit = 1000)
}

struct Setup {
    server: String,
    owner: Arc<Client>,
    vault: String,
    dir: tempfile::TempDir,
}

fn setup() -> Setup {
    let server = start_server();
    let email = format!("{}@example.com", passbox_core::id::new_id().unwrap());
    let owner = Client::new(&server, Arc::new(MemoryStore::new()));
    let secret_key = owner.sign_up(&email, PASSWORD).unwrap();
    let vault = owner.vaults().unwrap().remove(0).id;
    let mut data = ItemData::new(ItemCategory::Login, "Database");
    data.set_field(field::USERNAME, "Username", FieldType::Text, "admin");
    data.set_field(
        field::PASSWORD,
        "Password",
        FieldType::Concealed,
        "s3cr3t-db-pw",
    );
    owner.create_item(&vault, &data).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = pbx_raw(
        dir.path(),
        &[
            "signin",
            "--server",
            &server,
            "--email",
            &email,
            "--secret-key",
            &secret_key,
        ],
        &[],
        None,
    );
    assert!(out.0, "{}", out.2);
    Setup {
        server,
        owner: Arc::new(owner),
        vault,
        dir,
    }
}

fn pbx_raw(
    data_dir: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
    stdin: Option<&str>,
) -> (bool, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pbx"));
    command
        .args(args)
        .env("PASSBOX_DATA_DIR", data_dir)
        .env("PASSBOX_PASSWORD", PASSWORD)
        .env_remove("PASSBOX_SERVICE_ACCOUNT_TOKEN")
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        if let Some(text) = stdin {
            input.write_all(text.as_bytes()).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn pbx(s: &Setup, args: &[&str]) -> (bool, String, String) {
    pbx_raw(s.dir.path(), args, &[], None)
}

#[test]
fn create_edit_delete_and_json() {
    let s = setup();
    let (ok, out, err) = pbx_raw(
        s.dir.path(),
        &[
            "item",
            "create",
            "--title",
            "Staging API",
            "--username",
            "bot",
            "--url",
            "https://api.example.com",
            "--password-stdin",
            "--field",
            "Region=eu-1",
            "--tag",
            "staging",
            "--json",
        ],
        &[],
        Some("pw-from-stdin\n"),
    );
    assert!(ok, "{err}");
    let created: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(created["reference"], "pbx://Private/Staging API");
    let (ok, out, _) = pbx(&s, &["read", "pbx://Private/Staging API/password"]);
    assert!(ok);
    assert_eq!(out.trim(), "pw-from-stdin");

    let (ok, _, err) = pbx(
        &s,
        &[
            "item",
            "edit",
            "Staging API",
            "--generate-password",
            "--field",
            "Region=eu-2",
            "--remove-tag",
            "staging",
        ],
    );
    assert!(ok, "{err}");
    let (ok, out, _) = pbx(&s, &["--json", "item", "get", "Staging API"]);
    assert!(ok);
    let item: Value = serde_json::from_str(&out).unwrap();
    let password = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "password")
        .unwrap()["value"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(password.len(), 24);
    assert_eq!(item["passwordHistory"][0]["value"], "pw-from-stdin");
    assert!(item["tags"].as_array().unwrap().is_empty());
    assert!(out.contains("eu-2"));

    let (ok, out, _) = pbx(&s, &["item", "list", "--json", "--category", "login"]);
    assert!(ok);
    assert_eq!(
        serde_json::from_str::<Value>(&out)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Trash by default, permanent only when confirmed.
    let (ok, _, err) = pbx(&s, &["item", "delete", "Staging API"]);
    assert!(ok, "{err}");
    assert!(err.contains("trash"));
    s.owner.sync().unwrap();
    assert_eq!(s.owner.trashed_items().unwrap().len(), 1);
    let (ok, _, _) = pbx(&s, &["item", "delete", "Database", "--permanent"]);
    assert!(
        !ok,
        "permanent deletion without --yes and without a terminal must fail"
    );
    let (ok, _, _) = pbx(&s, &["item", "delete", "Database", "--permanent", "--yes"]);
    assert!(ok);
    s.owner.sync().unwrap();
    assert!(s.owner.items().unwrap().is_empty());
}

#[test]
fn inject_run_and_env() {
    let s = setup();
    let tpl = s.dir.path().join("config.tpl");
    std::fs::write(&tpl, "user={{ pbx://Private/Database/username }}\npass={{pbx://Private/Database/password}}\nkeep={{ other }}\n").unwrap();
    let out_path = s.dir.path().join("config.ini");
    let (ok, _, err) = pbx(
        &s,
        &[
            "inject",
            "-i",
            tpl.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(
        std::fs::read_to_string(&out_path).unwrap(),
        "user=admin\npass=s3cr3t-db-pw\nkeep={{ other }}\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // No overwrite without --force.
    let (ok, _, err) = pbx(
        &s,
        &[
            "inject",
            "-i",
            tpl.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ],
    );
    assert!(!ok && err.contains("--force"));
    // A missing reference writes nothing.
    std::fs::write(&tpl, "x={{ pbx://Private/Nope/password }}").unwrap();
    let (ok, out, _) = pbx_raw(
        s.dir.path(),
        &["inject", "-i", tpl.to_str().unwrap()],
        &[],
        None,
    );
    assert!(!ok && out.is_empty());

    // Environment items.
    let (ok, _, err) = pbx_raw(
        s.dir.path(),
        &[
            "item",
            "create",
            "--category",
            "environment",
            "--title",
            "API env",
            "--field",
            "API_KEY=-",
            "--field",
            "PORT:text=8080",
        ],
        &[],
        Some("k3y\"$x"),
    );
    assert!(ok, "{err}");
    let (ok, out, _) = pbx(&s, &["env", "API env"]);
    assert!(ok);
    assert_eq!(out, "API_KEY=\"k3y\\\"\\$x\"\nPORT=\"8080\"\n");
    let (ok, out, _) = pbx(
        &s,
        &[
            "env",
            "API env",
            "--",
            "sh",
            "-c",
            "printf %s \"$API_KEY:$PORT\"",
        ],
    );
    assert!(ok);
    assert_eq!(out, "k3y\"$x:8080");
    let (ok, out, _) = pbx(
        &s,
        &[
            "run",
            "--environment",
            "API env",
            "--",
            "sh",
            "-c",
            "printf %s \"$PORT\"",
        ],
    );
    assert!(ok);
    assert_eq!(out, "8080");
    let env_file = s.dir.path().join(".env.pbx");
    std::fs::write(&env_file, "DB=pbx://Private/Database/password\nPLAIN=yes\n").unwrap();
    let (ok, out, err) = pbx(
        &s,
        &[
            "run",
            "--env-file",
            env_file.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "printf %s \"$DB:$PLAIN\"",
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(out, "s3cr3t-db-pw:yes");

    let (ok, out, _) = pbx(&s, &["completions", "bash"]);
    assert!(ok && out.contains("pbx"));
}

#[test]
fn service_account_token() {
    let s = setup();
    let (_, token) = s
        .owner
        .create_service_account("CI", 0, &[(s.vault.clone(), Permission::Read)])
        .unwrap();
    let env = [
        ("PASSBOX_SERVICE_ACCOUNT_TOKEN", token.as_str()),
        ("PASSBOX_SERVER", s.server.as_str()),
        ("PASSBOX_PASSWORD", ""),
    ];
    // No account on this machine is needed.
    let other = tempfile::tempdir().unwrap();
    let (ok, out, err) = pbx_raw(
        other.path(),
        &["read", "pbx://Private/Database/password"],
        &env,
        None,
    );
    assert!(ok, "{err}");
    assert_eq!(out.trim(), "s3cr3t-db-pw");
    let (ok, out, _) = pbx_raw(
        other.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            "printf %s \"${PASSBOX_SERVICE_ACCOUNT_TOKEN:-scrubbed}\"",
        ],
        &env,
        None,
    );
    assert!(ok);
    assert_eq!(out, "scrubbed");
    // Read only.
    let (ok, _, err) = pbx_raw(
        other.path(),
        &["item", "create", "--title", "x"],
        &env,
        None,
    );
    assert!(!ok, "a read-only service account wrote");
    assert!(
        err.contains("no vault can be written to") || err.contains("read"),
        "{err}"
    );
}

struct Mcp {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next: u64,
}

impl Mcp {
    fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let message =
            json!({ "jsonrpc": "2.0", "id": self.next, "method": method, "params": params });
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], self.next);
        response
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        self.call(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )["result"]
            .clone()
    }
}

#[test]
fn mcp_server() {
    let s = setup();
    let (_, token) = s
        .owner
        .create_service_account("Agent", 0, &[(s.vault.clone(), Permission::Read)])
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pbx"))
        .arg("mcp")
        .env("PASSBOX_DATA_DIR", s.dir.path())
        .env("PASSBOX_SERVICE_ACCOUNT_TOKEN", token.as_str())
        .env("PASSBOX_SERVER", &s.server)
        .env_remove("PASSBOX_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut mcp = Mcp {
        child,
        stdin,
        stdout,
        next: 0,
    };

    let init = mcp.call("initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test-agent", "version": "1" } }));
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    writeln!(
        mcp.stdin,
        "{}",
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
    )
    .unwrap();
    let tools = mcp.call("tools/list", json!({}));
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 6);
    assert_eq!(mcp.call("nope", json!({}))["error"]["code"], -32601);

    let found = mcp.tool("passbox_search", json!({ "query": "data" }));
    let text = found["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("pbx://Private/Database/password"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");

    // The owner approves on "another device".
    let owner = s.owner.clone();
    std::thread::spawn(move || {
        for _ in 0..200 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(grant) = owner.agent_grants().unwrap_or_default().into_iter().next() {
                owner.decide_agent_grant(&grant, true, 0).unwrap();
                return;
            }
        }
    });
    let ran = mcp.tool(
        "passbox_run",
        json!({ "command": "echo \"pw=$DB\"", "env": { "DB": "pbx://Private/Database/password" }, "reason": "test", "wait_seconds": 20 }),
    );
    let text = ran["content"][0]["text"].as_str().unwrap();
    assert_eq!(ran["isError"], false, "{text}");
    assert!(text.contains("pw=[redacted DB]"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");

    // Unanswered requests do not run anything.
    let pending = mcp.tool(
        "passbox_run",
        json!({ "command": "echo other", "env": { "DB": "pbx://Private/Database/password" }, "wait_seconds": 0 }),
    );
    assert_eq!(pending["isError"], true);
    assert!(
        pending["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Waiting for the user's approval")
    );

    drop(mcp.stdin);
    let _ = mcp.child.wait();
    let kinds: Vec<String> = s
        .owner
        .activity(100)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(kinds.iter().any(|k| k == "agent_run"), "{kinds:?}");
}

/// A GitHub-style token assembled at run time (keeps this file clean for
/// other scanners).
fn test_token() -> String {
    format!("ghp_{}", "Zx81Qw7Lm3Pv".repeat(3))
}

#[test]
fn scan_reports_fixes_and_checks_staged_changes() {
    let s = setup();
    let project = tempfile::tempdir().unwrap();
    let env = project.path().join(".env");
    let token = test_token();
    std::fs::write(
        &env,
        format!("# config\nGITHUB_TOKEN={token}\nAPI_URL=https://api.example.com\nDB_PASSWORD=\"Xk9#mQ2$vL7pR4tZ\"\n"),
    )
    .unwrap();
    std::fs::write(
        project.path().join("README.md"),
        "Set API_KEY=your_api_key_here\n",
    )
    .unwrap();

    // Report: exit code 1, JSON without the values.
    let (ok, out, _) = pbx(&s, &["scan", project.path().to_str().unwrap(), "--json"]);
    assert!(!ok);
    assert!(
        !out.contains(&token) && !out.contains("Xk9#mQ2$vL7pR4tZ"),
        "{out}"
    );
    let report: Value = serde_json::from_str(&out).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{out}");
    assert_eq!(findings[0]["rule"], "github-token");
    assert_eq!(findings[0]["line"], 2);
    assert_eq!(findings[1]["variable"], "DB_PASSWORD");
    assert_eq!(report["filesScanned"], 2);

    // --fix without a terminal needs --yes.
    let (ok, _, err) = pbx(&s, &["scan", "--fix", env.to_str().unwrap()]);
    assert!(!ok);
    assert!(err.contains("--yes"), "{err}");

    let (ok, _, err) = pbx(&s, &["scan", "--fix", "--yes", env.to_str().unwrap()]);
    assert!(ok, "{err}");
    assert!(err.contains("Rotate"), "{err}");
    let rewritten = std::fs::read_to_string(&env).unwrap();
    assert!(
        !rewritten.contains(&token) && !rewritten.contains("Xk9#mQ2"),
        "{rewritten}"
    );
    assert!(rewritten.contains("API_URL=https://api.example.com"));
    let reference = rewritten
        .lines()
        .find_map(|l| l.strip_prefix("GITHUB_TOKEN="))
        .unwrap()
        .to_owned();
    assert!(reference.starts_with("pbx://"), "{rewritten}");
    assert!(rewritten.contains("DB_PASSWORD=\"pbx://"), "{rewritten}");

    // The reference resolves to the secret, and the item is in the vault.
    let (ok, out, err) = pbx(&s, &["read", &reference]);
    assert!(ok, "{err}");
    assert_eq!(out.trim(), token);
    s.owner.sync().unwrap();
    let item = s
        .owner
        .items()
        .unwrap()
        .into_iter()
        .find(|i| i.data.category == ItemCategory::Environment)
        .unwrap();
    assert!(item.data.title.ends_with("/.env"), "{}", item.data.title);
    assert_eq!(item.data.fields.len(), 2);
    assert!(
        item.data
            .fields
            .iter()
            .all(|f| f.field_type == FieldType::Concealed)
    );

    // A clean scan exits with 0.
    let (ok, _, err) = pbx(&s, &["scan", env.to_str().unwrap()]);
    assert!(ok, "{err}");

    // --staged scans only added lines of staged changes.
    let vcs = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(project.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    vcs(&["init", "-q"]);
    std::fs::write(
        project.path().join("deploy.sh"),
        format!("echo ok\nexport TOKEN={token}\n"),
    )
    .unwrap();
    std::fs::write(project.path().join("unstaged.sh"), format!("T={token}\n")).unwrap();
    vcs(&["add", "deploy.sh"]);
    let output = Command::new(env!("CARGO_BIN_EXE_pbx"))
        .args(["scan", "--staged", "--json"])
        .current_dir(project.path())
        .env("PASSBOX_DATA_DIR", s.dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["path"], "deploy.sh");
    assert_eq!(findings[0]["line"], 2);
}
