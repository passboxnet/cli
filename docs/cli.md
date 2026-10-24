# Command-line client (`pbx`)

`pbx` gives scripts, developers and CI pipelines access to Passbox. It uses the Rust client (`crates/client`), so it shares the encryption, sync and offline cache with the native apps.

## Install

```sh
cargo install --path crates/cli   # installs `pbx`
```

## Sign in

```sh
pbx signin --server https://passbox.example.com --email you@example.com
# prompts for the Secret Key and the master password
```

The account and an encrypted offline copy of the vault are stored in the data directory (`~/.local/share/passbox/cli` on Linux, the platform equivalent elsewhere; override with `--data-dir` or `PASSBOX_DATA_DIR`). Files are private to the current user.

Every vault command unlocks the account again. The master password is prompted for, or read from `PASSBOX_PASSWORD` for unattended use. When the server is not reachable, `pbx` reads from the offline copy.

With two-factor sign-in on, `pbx` asks for a code from the authenticator app or a recovery code (or reads it from `PASSBOX_TWO_FACTOR_CODE`) and remembers the machine for 30 days, so later commands only need the master password; set `PASSBOX_REMEMBER_DEVICE=0` to be asked every time. Security keys work in the web app only; on the command line use a code or a recovery code.

## Reading secrets

```sh
pbx list                                  # all items with IDs and vaults
pbx list --vault Work --json
pbx get GitHub                            # overview; concealed values are hidden
pbx get GitHub --field password           # prints one field
pbx get GitHub --field totp               # prints the current one-time code
pbx read pbx://Private/GitHub/password    # secret reference
```

Items are matched by ID, exact title or a unique part of the title. Fields are matched by ID (`username`, `password`, `url`, `totp`, …) or label; `notes` prints the notes.

## Injecting secrets into commands

Set environment variables to secret references and run the command through `pbx run`:

```sh
export DATABASE_PASSWORD=pbx://Work/Database/password
pbx run -- ./deploy.sh
```

`pbx run` resolves every variable whose value starts with `pbx://` and passes the secrets only to the child process. `PASSBOX_PASSWORD` is removed from the child's environment.

## Other commands

```sh
pbx status             # account on this machine
pbx signout            # removes the account and the offline copy
pbx generate -l 32     # password generator (also --pin, --no-symbols, --avoid-ambiguous)
pbx totp <secret>      # one-time code for an otpauth:// URI or Base32 secret
```

## Security notes

- Secrets are printed to standard output on request only. Avoid shell history and logs when passing `PASSBOX_PASSWORD`; prefer the prompt or a CI secret store.
- Changes (creating or editing items) are not supported in the CLI yet.
