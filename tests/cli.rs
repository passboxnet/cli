//! `pbx` against an in-process Passbox server.

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;

use passbox_client::{Client, FieldType, ItemCategory, ItemData, MemoryStore, field};
use passbox_server::config::Config;
use passbox_server::state::AppState;

const PASSWORD: &str = "correct horse battery staple";

fn start_server() -> String {
    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let db = passbox_server::db::connect("sqlite::memory:")
                .await
                .unwrap();
            let app = passbox_server::routes::router(
                &Config::default(),
                AppState::load(db).await.unwrap(),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

fn pbx(data_dir: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_pbx"))
        .args(args)
        .env("PASSBOX_DATA_DIR", data_dir)
        .env("PASSBOX_PASSWORD", PASSWORD)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn sign_in_read_secrets_and_run_commands() {
    let server = start_server();
    let email = format!("{}@example.com", passbox_core::id::new_id().unwrap());

    // Create the account and an item with the Rust client.
    let setup = Client::new(&server, Arc::new(MemoryStore::new()));
    let secret_key = setup.sign_up(&email, PASSWORD).unwrap();
    let vault = setup.vaults().unwrap().remove(0).id;
    let mut data = ItemData::new(ItemCategory::Login, "Database");
    data.set_field(field::USERNAME, "Username", FieldType::Text, "admin");
    data.set_field(
        field::PASSWORD,
        "Password",
        FieldType::Concealed,
        "s3cr3t-db-pw",
    );
    data.set_field(
        field::TOTP,
        "One-time password",
        FieldType::Totp,
        "JBSWY3DPEHPK3PXP",
    );
    setup.create_item(&vault, &data).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();

    let (ok, _, err) = pbx(data_dir, &["status"]);
    assert!(ok, "{err}");

    let (ok, _, err) = pbx(
        data_dir,
        &[
            "signin",
            "--server",
            &server,
            "--email",
            &email,
            "--secret-key",
            &secret_key,
        ],
    );
    assert!(ok, "{err}");
    assert!(err.contains("1 items"), "{err}");

    let (ok, out, _) = pbx(data_dir, &["status"]);
    assert!(ok && out.contains(&email));

    let (ok, out, err) = pbx(data_dir, &["list"]);
    assert!(ok, "{err}");
    assert!(out.contains("Database") && out.contains("Private"));

    let (ok, out, _) = pbx(data_dir, &["get", "data", "--field", "password"]);
    assert!(ok);
    assert_eq!(out.trim(), "s3cr3t-db-pw");

    // The overview hides concealed values.
    let (ok, out, _) = pbx(data_dir, &["get", "Database"]);
    assert!(ok && !out.contains("s3cr3t-db-pw") && out.contains("admin"));

    let (ok, out, _) = pbx(data_dir, &["get", "Database", "--field", "totp"]);
    assert!(ok && out.trim().len() == 6 && out.trim().chars().all(|c| c.is_ascii_digit()));

    let (ok, out, _) = pbx(data_dir, &["read", "pbx://Private/Database/username"]);
    assert!(ok);
    assert_eq!(out.trim(), "admin");

    let (ok, _, err) = pbx(data_dir, &["read", "pbx://Private/Nope/password"]);
    assert!(!ok && err.contains("no item matches"));

    // `run` injects resolved secrets into the child's environment only.
    let output = Command::new(env!("CARGO_BIN_EXE_pbx"))
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "printf %s \"$DB_PASSWORD\"; test -z \"$PASSBOX_PASSWORD\"",
        ])
        .env("PASSBOX_DATA_DIR", data_dir)
        .env("PASSBOX_PASSWORD", PASSWORD)
        .env("DB_PASSWORD", "pbx://Private/Database/password")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "s3cr3t-db-pw");

    // Wrong master password fails.
    let output = Command::new(env!("CARGO_BIN_EXE_pbx"))
        .args(["list"])
        .env("PASSBOX_DATA_DIR", data_dir)
        .env("PASSBOX_PASSWORD", "wrong")
        .output()
        .unwrap();
    assert!(!output.status.success());

    let (ok, _, _) = pbx(data_dir, &["signout"]);
    assert!(ok);
    let (ok, out, _) = pbx(data_dir, &["status"]);
    assert!(ok && out.contains("Not signed in"));
}
