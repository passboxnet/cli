# Command-line client (`pbx`)

`pbx` gives scripts, developers, CI pipelines and AI agents access to Passbox. It uses the Rust client (`crates/client`), so it shares the encryption, sync and offline cache with the native apps.

## Install

```sh
cargo install --path crates/cli   # installs `pbx`
```

Shell completions:

```sh
pbx completions bash > ~/.local/share/bash-completion/completions/pbx
pbx completions zsh  > "${fpath[1]}/_pbx"
pbx completions fish > ~/.config/fish/completions/pbx.fish
pbx completions powershell >> $PROFILE
```

## Sign in

```sh
pbx signin --server https://passbox.example.com --email you@example.com
# prompts for the Secret Key and the master password
```

The account and an encrypted offline copy of the vault are stored in the data directory (`~/.local/share/passbox/cli` on Linux, the platform equivalent elsewhere; override with `--data-dir` or `PASSBOX_DATA_DIR`). Files are private to the current user.

Every vault command unlocks the account again. The master password is prompted for, or read from `PASSBOX_PASSWORD` for unattended use. When the server is not reachable, `pbx` reads from the offline copy (changes need a connection).

With two-factor sign-in on, `pbx` asks for a code from the authenticator app or a recovery code (or reads it from `PASSBOX_TWO_FACTOR_CODE`) and remembers the machine for 30 days, so later commands only need the master password; set `PASSBOX_REMEMBER_DEVICE=0` to be asked every time. Security keys work in the web app only; on the command line use a code or a recovery code.

### Service accounts (CI, servers, agents)

Machines should not use your master password. Create a service account in the web app (**Developer → Service accounts**), give it access to selected vaults (read only, or read and write) and an expiry, and copy its token once. Then:

```sh
export PASSBOX_SERVER=https://passbox.example.com
export PASSBOX_SERVICE_ACCOUNT_TOKEN=pbx_sa_…   # from your CI secret store
pbx read pbx://CI/Database/password
```

Every vault command (`item`, `list`, `get`, `read`, `inject`, `run`, `env`, `mcp`) then uses the service account instead of the account on this machine. Nothing is written to disk. The token's secret never leaves the machine: `pbx` derives an authentication key for the server and decrypts the service account's private key locally. A service account never has more access than the person who created it; revoking it in the web app stops it at once. See [architecture/service-accounts.md](https://github.com/passboxnet/core/blob/main/docs/architecture/service-accounts.md).

## JSON output

Every command that prints data accepts `--json` (before or after the subcommand), for example `pbx --json item list` or `pbx item get GitHub --json`. Messages for people go to standard error, data to standard output.

## Items

```sh
pbx item list                                  # all items with IDs and vaults (no secrets)
pbx item list --vault Work --category login --tag prod --json
pbx item get GitHub                            # overview; concealed values are hidden
pbx item get GitHub --field password           # prints one field
pbx item get GitHub --field totp               # prints the current one-time code
pbx item get GitHub --json                     # the whole item, including secrets
```

`pbx list` and `pbx get` are short forms of `pbx item list` and `pbx item get`. Items are matched by ID, exact title or a unique part of the title (`--vault` narrows the search). Fields are matched by ID (`username`, `password`, `url`, `totp`, …) or label; `notes` prints the notes.

Creating and changing items:

```sh
pbx item create --vault Work --title "Staging DB" --username admin \
  --url https://db.staging.example.com --generate-password
printf %s "$TOKEN" | pbx item create --title "GitHub token" --category other \
  --field "token:concealed=-"                  # value from standard input
pbx item edit "Staging DB" --password-stdin < new-password.txt
pbx item edit "Staging DB" --field "Port=5432" --remove-field "Old note" --tag staging
pbx item delete "Staging DB"                   # to the trash, restorable for 30 days
pbx item delete "Staging DB" --permanent --yes # on all devices, cannot be undone
```

`--field LABEL=VALUE` sets or adds a field; `LABEL:TYPE=VALUE` chooses the type (`text`, `concealed`, `url`, `email`, `totp`). Pass secrets with `--password-stdin`, `--generate-password[=LENGTH]` or `=-` (standard input) rather than on the command line, where they end up in the shell history and the process list. A changed password is kept in the item's password history, as in the apps. Without `--vault`, `create` uses the only writable vault, or `Private`.

## Secret references

A secret reference names one field: `pbx://<vault>/<item>/<field>`. Vaults and items can be given by name or ID; use IDs when a name contains `/`. `pbx item create` and the JSON output of `pbx item get` print references.

```sh
pbx read pbx://Private/GitHub/password
```

### Templates: `pbx inject`

```sh
cat config.yml.tpl
# database:
#   user: {{ pbx://Work/Database/username }}
#   password: {{ pbx://Work/Database/password }}
pbx inject -i config.yml.tpl -o config.yml        # written with mode 0600
pbx inject < config.yml.tpl > /dev/stdout          # to standard output
```

Every `{{ pbx://… }}` is replaced; other `{{ … }}` (for example Helm or Jinja placeholders) stay as they are. An existing output file is only replaced with `--force`. If one reference cannot be resolved, nothing is written.

### Commands: `pbx run`

Set environment variables to secret references and run the command through `pbx run`:

```sh
export DATABASE_PASSWORD=pbx://Work/Database/password
pbx run -- ./deploy.sh
pbx run --env-file .env.pbx -- npm start          # KEY=pbx://… lines in a file you can commit
pbx run --environment "Staging API" -- npm start  # all variables of an environment item
```

`pbx run` resolves every variable whose value starts with `pbx://` and passes the secrets only to the child process. `PASSBOX_PASSWORD`, `PASSBOX_SERVICE_ACCOUNT_TOKEN`, `PASSBOX_TWO_FACTOR_CODE` and `PASSBOX_SECRET_KEY` are removed from the child's environment.

## Environments (`.env` files without the file)

An **environment** item holds key/value pairs: each field is a variable (label = name, value = value; concealed by default). Create them in the web app (New → Environment) or on the command line:

```sh
pbx item create --category environment --title "Staging API" \
  --field DATABASE_URL=postgres://staging.internal/app --field "API_KEY=-" < api-key.txt

pbx env "Staging API" -- npm start               # runs with the variables, nothing on disk
pbx env "Staging API" > .env                     # dotenv format (KEY="value")
eval "$(pbx env "Staging API" --format shell)"   # export into the current shell
pbx env "pbx://Work/Staging API" --json  # by reference, as JSON
```

Prefer `pbx env … -- <command>`: the values exist only in the child process's memory.

## AI agents: `pbx mcp`

`pbx mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server on standard input and output. Agents such as Claude Code, Claude Desktop, Cursor or VS Code can find items and *use* secrets (run a command, write a config file) without ever seeing them: secret values never appear in a tool result, command output is redacted, and every use needs your approval on another device (Passbox web or desktop app). There is no terminal prompt, because the agent could answer it.

Tools: `passbox_search` (metadata only), `passbox_request_access`, `passbox_check_access`, `passbox_run`, `passbox_inject`, `passbox_create_item`. Setup for each agent, the approval flow and the threat model are in [architecture/ai-agents.md](https://github.com/passboxnet/core/blob/main/docs/architecture/ai-agents.md).

Quick start with a service account limited to one vault (recommended):

```sh
claude mcp add passbox --env PASSBOX_SERVER=https://passbox.example.com \
  --env PASSBOX_SERVICE_ACCOUNT_TOKEN=pbx_sa_… -- pbx mcp
```

`pbx mcp --allow-reveal` (or `PASSBOX_MCP_ALLOW_REVEAL=1`) additionally offers `passbox_reveal`, which returns one value to the agent. It is off by default; each reveal still needs your approval with the box "Allow revealing the value to the agent" ticked, and organizations can forbid it for their vaults (policy `allowAgentReveal`). See [ai-agents.md](https://github.com/passboxnet/core/blob/main/docs/architecture/ai-agents.md#revealing-a-value-passbox_reveal).

`pbx mcp` never prompts. Without a service account token it needs `PASSBOX_PASSWORD` for the account on this machine. Actions are logged in your account's activity (and in `agent-audit.log` in the data directory).

## Finding leaked secrets: `pbx scan`

`pbx scan` looks for secrets in files, directories and staged changes: AWS access keys and secret keys, GitHub and GitLab tokens, Slack tokens and webhooks, Stripe secret keys, OpenAI, Anthropic, Google, npm and PyPI keys, private keys (PEM, OpenSSH, PGP), JSON Web Tokens, passwords in URLs (`postgres://user:password@host`) and long random values assigned to names like `*_TOKEN`, `*_SECRET`, `password` or `api_key`. It uses rules only; nothing leaves your machine and no AI is involved.

```sh
pbx scan                 # the current directory
pbx scan .env src/       # files and directories
pbx scan --staged        # only lines added in staged changes (for a pre-commit hook)
pbx scan --json          # findings as JSON
pbx scan --exclude fixtures --exclude .snap
```

Output names the file, line, column and kind, and shows only the first four characters and the length of each value, never the value:

```
.env:2:14  GitHub token  ghp_… (40 characters)  (GITHUB_TOKEN)
2 secrets found in 1 file (31 files scanned).
```

The exit code is 0 when nothing was found, 1 when secrets were found (and not fixed), and 2 on errors. `.git`, `node_modules`, `target`, `dist` and similar directories, lockfiles, binary files and files over 2 MB are skipped. To keep few false positives, placeholders (`your_api_key_here`, `changeme`, `${VAR}`, `<token>`, `…EXAMPLE`), code (`process.env.X`, `config.token`, function calls) and references (`pbx://…`) are not reported. To silence a false positive, add `pbx-scan:ignore` anywhere on its line.

### Moving secrets into Passbox: `--fix`

```sh
pbx scan --fix .env          # asks for each secret
pbx scan --fix --yes .env    # fixes all (for scripts)
pbx scan --fix --vault Dev config/
```

For every file, `--fix` stores the chosen secrets as hidden fields of one new **environment** item (titled `<folder>/<file>`, field names from the variable names, tag `pbx-scan`) and replaces each value in the file with a reference:

- In `.env`-style files the value becomes the reference itself (`GITHUB_TOKEN=pbx://Private/<item>/GITHUB_TOKEN`), so the file works with `pbx run --env-file .env -- <command>`.
- In other files it becomes a template marker (`{{ pbx://Private/<item>/API_KEY }}`); render the file with `pbx inject -i <file> -o <output>`.

Private keys are reported but not rewritten; store key files with `pbx item create`. `--fix` cannot be combined with `--staged`. **Rotate every secret `--fix` moved**: the old value may still be in your history, in backups, in logs or with whoever cloned the repository.

### Pre-commit hook

`.git/hooks/pre-commit` (make it executable with `chmod +x`):

```sh
#!/bin/sh
# Refuse commits that add secrets. Bypass once with: git commit --no-verify
exec pbx scan --staged
```

With the [pre-commit](https://pre-commit.com) framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pbx-scan
        name: pbx scan
        entry: pbx scan --staged
        language: system
        pass_filenames: false
```

`pbx scan` needs no sign-in, so the hook also works on machines without a Passbox account.

## CI: GitHub Actions

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      PASSBOX_SERVER: https://passbox.example.com
      PASSBOX_SERVICE_ACCOUNT_TOKEN: ${{ secrets.PASSBOX_SERVICE_ACCOUNT_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - name: Install pbx
        run: cargo install --locked --git https://github.com/passboxnet/cli passbox-cli
      - name: Deploy
        env:
          DATABASE_URL: pbx://CI/Production database/url
          DEPLOY_KEY: pbx://CI/Deploy key/password
        run: pbx run -- ./scripts/deploy.sh
      - name: Render the config
        run: pbx inject -i config/prod.tpl -o config/prod.yml
```

Give the CI service account read access to a dedicated vault, an expiry, and store only its token in the repository's secrets. GitHub masks the token itself; values `pbx run` injects are not known to GitHub, so make sure your scripts do not print them. GitLab CI and other systems work the same way (`PASSBOX_SERVICE_ACCOUNT_TOKEN` as a masked, protected variable).

## Other commands

```sh
pbx status             # account (and service account) on this machine
pbx signout            # removes the account and the offline copy
pbx generate -l 32     # password generator (also --pin, --no-symbols, --avoid-ambiguous)
pbx totp <secret>      # one-time code for an otpauth:// URI or Base32 secret
```

## Security notes

- Secrets are printed to standard output on request only (`get --field`, `read`, `env` without a command, `inject` without `-o`). Avoid shell history and logs when passing `PASSBOX_PASSWORD`; prefer the prompt, a service account, or a CI secret store.
- `pbx env` and `pbx inject -o` write secrets only where you ask; `pbx run` and `pbx env -- <command>` keep them in the child process.
- A service account token is as powerful as the vault access you gave it. Give it the smallest set of vaults, read only where possible, and an expiry. Revoke it in the web app when a machine is retired or the token may have leaked.
