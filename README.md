# Passbox CLI

`pbx`, the command-line client of [Passbox](https://passbox.net), an open-source password manager with passkeys, a built-in authenticator and single sign-on. It also runs an MCP server, so AI agents get exactly the secrets a service account allows. See [docs/cli.md](docs/cli.md).

## Development

```sh
cargo build
cargo run -- totp JBSWY3DPEHPK3PXP
PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test
```

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
