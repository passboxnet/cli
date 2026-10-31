# Passbox CLI

`pbx`, the command-line client of [Passbox](https://passbox.net), an open-source password manager with passkeys, a built-in authenticator and single sign-on. It also runs an MCP server, so AI agents get exactly the secrets a service account allows. See [docs/cli.md](docs/cli.md).

> **Status: early development.** The cryptographic design is a draft and has not been audited. Do not store real secrets in Passbox yet.

## Development

```sh
cargo build
cargo run -- totp JBSWY3DPEHPK3PXP
PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test
```

The tests start a real server from [passbox-server](https://github.com/passboxnet/passbox-server) (a git dev-dependency). The client library comes from [passbox-core](https://github.com/passboxnet/passbox-core).

## Repositories

| Repository | Contents |
| --- | --- |
| [passbox-core](https://github.com/passboxnet/passbox-core) | Cryptographic core (Rust), WebAssembly build, Rust client, Swift/Kotlin bindings, AI gateway, shared TypeScript packages (`@passbox/*`) |
| [passbox-server](https://github.com/passboxnet/passbox-server) | Server (API, sync, web vault hosting), container image, Docker Compose for self-hosting |
| [passbox-web](https://github.com/passboxnet/passbox-web) | Web vault (React, Vite) and browser end-to-end tests |
| [passbox-extension](https://github.com/passboxnet/passbox-extension) | Browser extension with autofill and passkeys |
| [passbox-desktop](https://github.com/passboxnet/passbox-desktop) | Desktop app for Windows, macOS and Linux (Tauri) |
| [passbox-ios](https://github.com/passboxnet/passbox-ios) | iOS and iPadOS app |
| [passbox-android](https://github.com/passboxnet/passbox-android) | Android app |
| [passbox-cli](https://github.com/passboxnet/passbox-cli) | `pbx` command-line client and MCP server |

## License

[MIT](LICENSE)
