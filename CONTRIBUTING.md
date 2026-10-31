# Contributing to Passbox

Thanks for your interest in Passbox! This document explains how the repository is organized and what we expect from changes.

## Conventions

- **Language:** code, comments, commit messages and technical documentation are written in English.
- **Repositories:** Passbox is split into several repositories (see the [README](README.md#repositories)). This one is the `pbx` command-line client. It uses the Rust client and the core from passboxnet/core through a git dependency on a release tag.
- **Cryptography lives only in [passboxnet/core](https://github.com/passboxnet/core).** `pbx` calls it through the Rust client. Do not add cryptographic code here.
- **No secrets in logs, errors or `Debug` output.** Secret types redact themselves; keep it that way.

## Database for tests

The tests start a real Passbox server, which needs PostgreSQL 15 or newer. For example:

```sh
docker run -d --name passbox-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
export PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres
```

`PASSBOX_TEST_DATABASE_URL` is a superuser connection. Every server the tests start gets a database of its own with the production roles, which is dropped afterwards. The server comes from [passboxnet/server](https://github.com/passboxnet/server) as a git dev-dependency.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests need `PASSBOX_TEST_DATABASE_URL` (above).

Significant design decisions are recorded as ADRs in [passboxnet/core: `docs/adr`](https://github.com/passboxnet/core/tree/main/docs/adr). Add one when you change the architecture, the cryptography or a public interface.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
