# Passbox CLI

`pbx`, the command-line client of [Passbox](https://passbox.net), an open-source password manager with passkeys, a built-in authenticator and single sign-on. It also runs an MCP server, so AI agents get exactly the secrets a service account allows. See [docs/cli.md](docs/cli.md).

## Install

On macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/passboxnet/cli/main/install.sh | sh
```

This downloads the latest release for your system, verifies its SHA-256 checksum and installs `pbx` to `~/.local/bin` (change it with `PBX_INSTALL_DIR`, pick a version with `PBX_VERSION`). It never asks for root.

On Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/passboxnet/cli/main/install.ps1 | iex
```

Then sign in with your browser, where you are signed in to Passbox already:

```sh
pbx login                                        # the Passbox cloud
pbx login --server https://passbox.example.com   # a self-hosted server
```

Approve the request in the browser and type your master password in the terminal; it never leaves your machine. For CI and other machines without a person at the keyboard, use a service account token instead (`PASSBOX_SERVICE_ACCOUNT_TOKEN`); `pbx` never prompts or opens a browser there. See [docs/cli.md](docs/cli.md#sign-in) and [CI and headless](docs/cli.md#ci-and-headless).

You can also download an archive for your platform from the [releases](https://github.com/passboxnet/cli/releases) and check it against `SHA256SUMS`, or build from source with Rust: `cargo install --locked --git https://github.com/passboxnet/cli passbox-cli`. Details, including how to verify the build provenance, are in [docs/cli.md](docs/cli.md#install).

## Development

```sh
cargo build
cargo run -- totp JBSWY3DPEHPK3PXP
PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test
```

The browser sign-in tests drive `pbx` in a pseudo-terminal (Unix only).

The tests start a real server from [passboxnet/server](https://github.com/passboxnet/server) (a git dev-dependency). The client library comes from [passboxnet/core](https://github.com/passboxnet/core).

## Repositories

| Repository | Contents |
| --- | --- |
| [passboxnet/core](https://github.com/passboxnet/core) | Cryptographic core (Rust), WebAssembly build, Rust client, Swift/Kotlin bindings, AI gateway, shared TypeScript packages (`@passbox/*`) |
| [passboxnet/server](https://github.com/passboxnet/server) | Server (API, sync, web vault hosting), container image, Docker Compose for self-hosting |
| [passboxnet/web](https://github.com/passboxnet/web) | Web vault (React, Vite) and browser end-to-end tests |
| [passboxnet/browser-extension](https://github.com/passboxnet/browser-extension) | Browser extension with autofill and passkeys |
| [passboxnet/desktop](https://github.com/passboxnet/desktop) | Desktop app for Windows, macOS and Linux (Tauri) |
| [passboxnet/ios](https://github.com/passboxnet/ios) | iOS and iPadOS app |
| [passboxnet/android](https://github.com/passboxnet/android) | Android app |
| [passboxnet/cli](https://github.com/passboxnet/cli) | `pbx` command-line client and MCP server |

## License

[MIT](LICENSE)
