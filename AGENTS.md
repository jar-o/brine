# AGENTS.md

Guidance for AI agents and contributors working on `brine`. See `README.md` for what the tool does and how to use it.

## What this is

`brine` is a Rust CLI (edition 2024, single binary crate) that encrypts a file with age, uploads the ciphertext to Walrus, and manages the passphrase-protected private key under `~/.brine/<blob-id>/`. It has two commands: `store` and `fetch`.

## Layout

```
Cargo.toml / Cargo.lock   walrus-sdk is a git dependency pinned by commit; the lock file came from the Walrus repo
src/main.rs               clap CLI, `store` and `fetch` flows, the upload confirmation prompt
src/vault.rs              age encryption and decryption, key wrapping, unit tests
src/keystore.rs           on-disk key store (~/.brine), passphrase prompt, private file/dir creation
src/walrus.rs             Walrus SDK access: config loading, upload, download
aux/                      README assets
```

### Responsibilities

- **main.rs**: argument parsing and orchestration only. Crypto stays in `vault`, file handling in `keystore`, network in `walrus`.
- **vault.rs**
  - `seal(plaintext, count, supplied, passphrase)` encrypts to `count` newly generated X25519 identities plus the `supplied` public recipients. It returns a `Bundle` with the ciphertext, the passphrase-wrapped new key files (`key-N.age`) and the `recipients.txt` text.
  - `open(ciphertext, key_files, passphrase)` tries each key file and returns the first successful decryption.
  - `parse_recipient` accepts native `age1...` keys only.
  - A key file is an age file encrypted with the scrypt passphrase recipient. Its content is one `AGE-SECRET-KEY-...` line, with no comment lines.
- **keystore.rs**: `stage()` writes keys to `<root>/.pending-*`, `commit()` renames the directory to `<root>/<blob-id>`, and `discard()` removes it. `keys_for()` lists `*.age` files for a blob ID. `BRINE_HOME` overrides the root.
- **walrus.rs**: `load_config()` uses the standard Walrus config locations. If no config file exists, it falls back to the SDK's built-in default for `https://fullnode.<context>.sui.io`. `store()` needs a funded Sui wallet. `fetch()` is read-only.

## Store flow and invariants

1. Read the file, parse `--recipient` values, and ask for a new passphrase only if no recipient was given (a key is generated).
2. Encrypt with `vault::seal`.
3. **Stage the key files on disk before uploading.**
4. Ask for confirmation unless `--do-it` is set. Declining discards the staging directory.
5. Upload. On failure the staging directory is discarded and the error says no keys were kept. On success `commit()` renames it to `<root>/<blob-id>`.

Keep these properties when changing the code:

- The ciphertext must never reach Walrus unless its keys are already saved. Do not move the staging step after the upload.
- If `commit()` fails after a successful upload, it leaves the staging directory in place and reports its path, because these are the only keys. Do not delete it.
- Without `--recipient`, exactly one key is generated and it is the only recipient. There is no option to generate several keys. To make backups, copy the one key file.
- Key and output files are created with `create_new` and mode 0600, and directories with 0700. Never overwrite an existing file. `fetch` refuses an existing `--out`.
- The blob ID becomes a path component, so `keys_for` restricts it to `[A-Za-z0-9_-]`. Keep that check.
- Passphrases are read with `rpassword` (no echo) and held as `SecretString`. Never log or print them or the private keys.
- Long options only (`--out`, not `-out` or `-o`). Don't add single-dash flags.

## Wipe flow

`brine wipe <blob-id>` calls `walrus::delete`, which uses `WalrusNodeClient::delete_owned_blob`. That only deletes blobs that are deletable and owned by the wallet. `store` relies on `StoreArgs::default_with_epochs` being deletable, so do not switch uploads to permanent without updating `wipe`. Wipe never touches the local key directory. It is untested against a live network.

## Conventions

- `--context` defaults to `mainnet`. Pass `testnet` to avoid spending real funds when testing.
- Errors use `anyhow` with context that tells the user what to do next.
- Run `cargo fmt` and `cargo clippy` before finishing, and keep both clean.

## Build and test

```bash
cargo build
cargo test        # local only: no network, wallet, or funds needed
cargo clippy
```

- The first build compiles the Walrus SDK and takes a while.
- Unit tests live in `vault.rs` and cover: any single generated key decrypts, wrong passphrase fails, a key from another blob fails, one or several external recipients decrypt without a generated key, and malformed recipients are rejected.
- Nothing automated covers the Walrus upload and download or the CLI flows. To check them, run a real testnet round trip:
  ```bash
  brine store --context testnet small.txt
  brine fetch <blob-id> --context testnet --out small.out.txt
  ```
  This spends testnet SUI and WAL (`walrus get-wal --context testnet`). Do not run it, or any mainnet upload, without the user's go-ahead.
- Set `BRINE_HOME` to a scratch directory when testing so you don't touch the real `~/.brine`.

## Dependencies

- `walrus-sdk` is not on crates.io. It is pinned to the Walrus commit matching the v1.62.0 CLI (`2bd352b6`), and `Cargo.lock` is copied from that repo so shared dependency versions line up. When bumping, change the `rev`, take the lock file from the same Walrus commit, and rebuild. SDK APIs change between releases.
- `age` 0.12 provides the encryption. Only native X25519 recipients and scrypt are supported.

## Known limits and ideas

- Plugin recipients (for example `age-plugin-yubikey`, `age1yubikey1...`) are not supported by `store` or `fetch`. Supporting them needs the `age` crate's plugin feature on both sides. For now, a blob encrypted to a plugin key must be downloaded with `walrus read` and opened with the `age` CLI.
- `fetch --key` opens only brine-style key files (passphrase-wrapped X25519 identity). Keys from `age-keygen` need `grep '^AGE-SECRET-KEY' | age -p` wrapping first.
- Walrus blobs are public and permanent for their paid epochs, so the key and passphrase are the only protection against harvest-now-decrypt-later attacks.
