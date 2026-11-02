//! Signing in with the browser (`pbx login`) and the behavior without a
//! terminal or with `CI` set, against an in-process server.

use std::process::{Command, Stdio};
use std::sync::Arc;

use passbox_client::{Client, FieldType, ItemCategory, ItemData, MemoryStore, field};
use passbox_core::service_account::Permission;

const PASSWORD: &str = "correct horse battery staple";

fn start_server() -> String {
    passbox_server::testing::spawn_server(|state, _| state.auth_rate_limit = 1000)
}

/// An account with one item, signed in with the Rust client (the "browser").
fn account(server: &str) -> (Client, String, String) {
    let email = format!("{}@example.com", passbox_core::id::new_id().unwrap());
    let client = Client::new(server, Arc::new(MemoryStore::new()));
    let secret_key = client.sign_up(&email, PASSWORD).unwrap();
    let vault = client.vaults().unwrap().remove(0).id;
    let mut data = ItemData::new(ItemCategory::Login, "Database");
    data.set_field(
        field::PASSWORD,
        "Password",
        FieldType::Concealed,
        "s3cr3t-db-pw",
    );
    client.create_item(&vault, &data).unwrap();
    (client, email, secret_key)
}

/// `pbx` without a terminal: standard input from /dev/null, output captured.
fn headless(
    data_dir: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_pbx"))
        .args(args)
        .env("PASSBOX_DATA_DIR", data_dir)
        .env_remove("PASSBOX_PASSWORD")
        .env_remove("PASSBOX_SERVICE_ACCOUNT_TOKEN")
        .env_remove("PASSBOX_SERVER")
        .env_remove("PASSBOX_EMAIL")
        .env_remove("CI")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn without_a_terminal_pbx_never_prompts_or_opens_a_browser() {
    let dir = tempfile::tempdir().unwrap();
    for env in [&[][..], &[("CI", "true")][..]] {
        // `pbx` alone prints the status and how to use a service account.
        let (ok, out, err) = headless(dir.path(), &[], env);
        assert!(ok, "{err}");
        assert!(out.contains("Not signed in."), "{out}");
        assert!(out.contains("PASSBOX_SERVICE_ACCOUNT_TOKEN"), "{out}");
        assert!(!out.contains("Press Enter") && !err.contains("Press Enter"));

        // `pbx login` fails at once with the same advice.
        for args in [
            &["login"][..],
            &["signin", "--server", "http://127.0.0.1:9"][..],
        ] {
            let (ok, out, err) = headless(dir.path(), args, env);
            assert!(!ok);
            assert!(
                !out.contains("cli-login"),
                "no link without a terminal: {out}"
            );
            assert!(err.contains("PASSBOX_SERVICE_ACCOUNT_TOKEN"), "{err}");
            assert!(err.contains("docs/cli.md#ci-and-headless"), "{err}");
        }
        // The manual sign-in does not prompt for a missing Secret Key.
        let (ok, _, err) = headless(
            dir.path(),
            &[
                "login",
                "--server",
                "http://127.0.0.1:9",
                "--email",
                "a@example.com",
            ],
            env,
        );
        assert!(!ok);
        assert!(err.contains("--secret-key"), "{err}");
    }
    let (_, _, err) = headless(dir.path(), &["login"], &[("CI", "true")]);
    assert!(err.contains("CI is set"), "{err}");
    let (_, _, err) = headless(dir.path(), &["login"], &[]);
    assert!(err.contains("not an interactive terminal"), "{err}");
    let (_, _, err) = headless(dir.path(), &["login"], &[("CI", "false")]);
    assert!(err.contains("not an interactive terminal"), "{err}");
}

#[test]
fn headless_commands_work_with_a_service_account_or_fail_fast() {
    let server = start_server();
    let (owner, email, secret_key) = account(&server);
    let vault = owner.vaults().unwrap().remove(0).id;
    let (_, token) = owner
        .create_service_account("CI", 0, &[(vault, Permission::Read)])
        .unwrap();

    // A signed-in machine without PASSBOX_PASSWORD: no prompt, a clear error.
    let dir = tempfile::tempdir().unwrap();
    let (ok, _, err) = headless(
        dir.path(),
        &[
            "login",
            "--server",
            &server,
            "--email",
            &email,
            "--secret-key",
            &secret_key,
        ],
        &[("PASSBOX_PASSWORD", PASSWORD), ("CI", "true")],
    );
    assert!(ok, "the manual sign-in works unattended: {err}");
    for env in [&[][..], &[("CI", "true")][..]] {
        let (ok, _, err) = headless(dir.path(), &["list"], env);
        assert!(!ok);
        assert!(err.contains("master password is needed"), "{err}");
        assert!(err.contains("PASSBOX_SERVICE_ACCOUNT_TOKEN"), "{err}");
        // `pbx` alone shows the status, also when signed in.
        let (ok, out, _) = headless(dir.path(), &[], env);
        assert!(
            ok && out.contains(&email) && out.contains("pbx list"),
            "{out}"
        );
    }
    let (ok, out, _) = headless(
        dir.path(),
        &["list"],
        &[("PASSBOX_PASSWORD", PASSWORD), ("CI", "true")],
    );
    assert!(ok && out.contains("Database"), "{out}");

    // A service account needs nothing on the machine, with CI set.
    let empty = tempfile::tempdir().unwrap();
    let env = [
        ("CI", "true"),
        ("PASSBOX_SERVICE_ACCOUNT_TOKEN", token.as_str()),
        ("PASSBOX_SERVER", server.as_str()),
    ];
    let (ok, out, err) = headless(
        empty.path(),
        &["read", "pbx://Private/Database/password"],
        &env,
    );
    assert!(ok, "{err}");
    assert_eq!(out.trim(), "s3cr3t-db-pw");
    let (ok, out, err) = headless(
        empty.path(),
        &["run", "--", "sh", "-c", "printf %s \"$DB\""],
        &[
            env[0],
            env[1],
            env[2],
            ("DB", "pbx://Private/Database/password"),
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(out, "s3cr3t-db-pw");
    let template = empty.path().join("config.tpl");
    std::fs::write(
        &template,
        "password: {{ pbx://Private/Database/password }}\n",
    )
    .unwrap();
    let (ok, out, err) = headless(
        empty.path(),
        &["inject", "-i", template.to_str().unwrap()],
        &env,
    );
    assert!(ok, "{err}");
    assert_eq!(out, "password: s3cr3t-db-pw\n");
    let (ok, out, _) = headless(empty.path(), &[], &env);
    assert!(ok && out.contains("Service account"), "{out}");
    // Without PASSBOX_SERVER (and no account here), the error says so.
    let (ok, _, err) = headless(
        empty.path(),
        &["read", "pbx://Private/Database/password"],
        &[env[0], env[1]],
    );
    assert!(!ok && err.contains("PASSBOX_SERVER"), "{err}");
}

#[cfg(unix)]
mod terminal {
    use std::process::Command;
    use std::time::Duration;

    use rexpect::session::{PtySession, spawn_command};

    use super::*;

    fn pbx(dir: &std::path::Path, args: &[&str], password_env: bool) -> PtySession {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pbx"));
        command
            .args(args)
            .env("PASSBOX_DATA_DIR", dir)
            .env_remove("CI")
            .env_remove("PASSBOX_SERVICE_ACCOUNT_TOKEN")
            .env_remove("PASSBOX_SERVER")
            .env_remove("PASSBOX_EMAIL")
            .env_remove("PASSBOX_SECRET_KEY")
            .env("TERM", "dumb");
        if password_env {
            command.env("PASSBOX_PASSWORD", PASSWORD);
        } else {
            command.env_remove("PASSBOX_PASSWORD");
        }
        spawn_command(command, Some(30_000)).unwrap()
    }

    /// The ID and secret of the printed link.
    fn link(session: &mut PtySession, server: &str) -> (String, String) {
        session
            .exp_string("Open this link in a browser where you are signed in to Passbox:")
            .unwrap();
        let (_, url) = session
            .exp_regex(r"http\S+#/cli-login/[0-9a-z]{26}#[A-Za-z0-9_-]{43}")
            .unwrap();
        assert!(url.starts_with(&format!("{server}/#/cli-login/")), "{url}");
        let rest = url.split("#/cli-login/").nth(1).unwrap();
        let (id, secret) = rest.split_once('#').unwrap();
        (id.to_owned(), secret.to_owned())
    }

    /// Whether pbx exited with status 0.
    fn exited_ok(session: PtySession) -> bool {
        let mut session = session;
        session.exp_eof().ok();
        matches!(
            session.process().wait().unwrap(),
            rexpect::process::WaitStatus::Exited(_, 0)
        )
    }

    #[test]
    fn sign_in_with_the_browser() {
        let server = start_server();
        let (browser, email, _) = account(&server);
        let dir = tempfile::tempdir().unwrap();

        // `pbx` alone offers the browser sign-in; the server comes from
        // PASSBOX_SERVER here (the default is https://app.passbox.net).
        let mut command = Command::new(env!("CARGO_BIN_EXE_pbx"));
        command
            .env("PASSBOX_DATA_DIR", dir.path())
            .env("PASSBOX_SERVER", &server)
            .env_remove("CI")
            .env_remove("PASSBOX_PASSWORD")
            .env_remove("PASSBOX_SERVICE_ACCOUNT_TOKEN")
            .env("SSH_CONNECTION", "test")
            .env("TERM", "dumb");
        let mut session = spawn_command(command, Some(30_000)).unwrap();
        session.exp_string("You are not signed in.").unwrap();
        session
            .exp_string("Press Enter to sign in with your browser (or Ctrl+C to cancel)...")
            .unwrap();
        session.send_line("").unwrap();
        let (id, secret) = link(&mut session, &server);

        // The browser sees the device's name and approves.
        let info = browser.cli_login_request(&id, &secret).unwrap();
        assert!(info.device_name.starts_with("pbx"), "{info:?}");
        // A wrong secret is detected and nothing is sent.
        let other = passbox_core::encoding::encode(&[9u8; 32]);
        assert!(browser.approve_cli_login(&id, &other).is_err());
        browser.approve_cli_login(&id, &secret).unwrap();

        // (rexpect reads bytes as Latin-1, so match after the check mark.)
        session.exp_string("Waiting for approval... ").unwrap();
        session.exp_string(&email).unwrap();
        session.exp_string("Master password:").unwrap();
        session.send_line("wrong password").unwrap();
        session
            .exp_string("wrong master password, try again")
            .unwrap();
        session.exp_string("Master password:").unwrap();
        session.send_line(PASSWORD).unwrap();
        session
            .exp_string(&format!("Signed in as {email}"))
            .unwrap();
        session.exp_string("Vaults: Private").unwrap();
        assert!(exited_ok(session));

        // Signed in: the next command uses the account, `pbx` shows the status.
        let (ok, out, err) = headless(dir.path(), &["list"], &[("PASSBOX_PASSWORD", PASSWORD)]);
        assert!(ok && out.contains("Database"), "{err}");
        let mut session = pbx(dir.path(), &[], false);
        session
            .exp_string(&format!("Signed in as {email} on {server}"))
            .unwrap();
        assert!(exited_ok(session));
    }

    #[test]
    fn deny_and_ctrl_c() {
        let server = start_server();
        let (browser, _, _) = account(&server);
        let dir = tempfile::tempdir().unwrap();

        let mut session = pbx(
            dir.path(),
            &["login", "--server", &server, "--no-browser"],
            true,
        );
        let (id, _) = link(&mut session, &server);
        session.exp_string("Waiting for approval...").unwrap();
        browser.deny_cli_login(&id).unwrap();
        session
            .exp_string("the sign-in was denied in the browser")
            .unwrap();
        assert!(!exited_ok(session));

        // Ctrl+C withdraws the request on the server.
        let mut session = pbx(
            dir.path(),
            &["signin", "--server", &server, "--no-browser"],
            true,
        );
        let (id, secret) = link(&mut session, &server);
        session.exp_string("Waiting for approval...").unwrap();
        assert!(browser.cli_login_request(&id, &secret).is_ok());
        session.send_control('c').unwrap();
        session
            .exp_string("Cancelled. The sign-in request was withdrawn.")
            .unwrap();
        assert!(!exited_ok(session));
        std::thread::sleep(Duration::from_millis(200));
        assert!(browser.cli_login_request(&id, &secret).is_err());
        let (_, out, _) = headless(dir.path(), &["status"], &[]);
        assert!(out.contains("Not signed in."), "{out}");
    }

    #[test]
    fn ci_wins_over_a_terminal() {
        let dir = tempfile::tempdir().unwrap();
        for args in [&["login"][..], &[][..]] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_pbx"));
            command
                .args(args)
                .env("PASSBOX_DATA_DIR", dir.path())
                .env("CI", "true")
                .env_remove("PASSBOX_SERVICE_ACCOUNT_TOKEN")
                .env("TERM", "dumb");
            let mut session = spawn_command(command, Some(10_000)).unwrap();
            if args.is_empty() {
                session.exp_string("Not signed in.").unwrap();
                assert!(exited_ok(session));
            } else {
                session.exp_string("CI is set").unwrap();
                assert!(!exited_ok(session));
            }
        }
    }
}
