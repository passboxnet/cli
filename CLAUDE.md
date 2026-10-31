# Notes for AI coding agents

- Code, comments, commits and technical docs: **English**.
- Passbox is split into repositories (see README). This one is the `pbx` CLI; it uses passboxnet/core through a git dependency on a release tag.
- No cryptography here: it belongs in passboxnet/core.
- Checks: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test` (needs `PASSBOX_TEST_DATABASE_URL`).
- No AI attribution in commits or PRs (`git config core.hooksPath .githooks`).
