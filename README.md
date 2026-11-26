![corpus](aux/logo.png)

Encrypt a file with [age](https://age-encryption.org), store the ciphertext on [Walrus](https://www.walrus.xyz), and keep the key safe locally.

## What it does

- `brine store` encrypts a file, uploads the ciphertext to Walrus (mainnet by default, or testnet).
  - With no `--recipient`, it generates one new age key, protects it with a passphrase you choose, and moves it to `~/.brine/<blob-id>/`.
  - With one or more `--recipient age1...` public keys, it encrypts to those keys instead. Any one of them can decrypt. No key is generated and no passphrase is asked.
- `brine fetch` downloads a blob from Walrus and decrypts it to `--out`, asking for the key passphrase.

The key is saved before the upload starts. If the upload fails, it is discarded, so the ciphertext never exists on Walrus without its key.

## Usage

```bash
# Encrypt to a new key and upload (asks for confirmation unless --do-it)
brine store --context testnet --epochs 5 secret.txt

# Encrypt to existing public keys
brine store --recipient age1... --recipient age1... secret.txt

# Download and decrypt (keys are read from ~/.brine/<blob-id>/)
brine fetch <blob-id> --context testnet --out secret.txt

# Use a key file from somewhere else, such as a USB stick
brine fetch <blob-id> --key /Volumes/USB/key-1.age --out secret.txt
```

## Deleting a blob

```bash
brine wipe <blob-id> --context testnet
```

`brine store` uploads deletable blobs, and `brine wipe` deletes them using the wallet that stored them. It asks for confirmation unless `--do-it` is given, and it leaves `~/.brine/<blob-id>/` alone. Deleting frees the storage on Walrus but cannot recall copies that anyone already downloaded, and nodes may serve the data until they clean it up. It fails if the wallet owns no deletable blob with that ID.

## Non-interactive use

Both commands take `--passphrase-file <path>`, which reads the first line of the file instead of prompting. Use `-` to read it from stdin, for example from a keychain or password manager:

```bash
security find-generic-password -s brine -w | brine fetch <blob-id> --passphrase-file - --out secret.txt
```

A passphrase file must not be accessible by group or others (`chmod 600`). Keeping it next to the key files defeats the passphrase, so prefer stdin from a secret store. For `store`, the flag sets the passphrase for a newly generated key, and it is an error together with `--recipient`.

## Things to know

- Uploading spends SUI (gas) and WAL (storage) from your Sui wallet.
- Walrus blobs are public. The ciphertext can be copied by anyone for a HNDL attack. `brine` encrypts all files with a randomly generated key file, no reliance on "strenthening" a passprhase.
- Key files are age files wrapped with a passphrase (scrypt). Back them up by copying them to other places.
- Set `BRINE_HOME` to use a directory other than `~/.brine`.

## Build and test

```bash
cargo build --release   # binary at target/release/brine
cargo test
```

`walrus-sdk` is a git dependency pinned to a Walrus commit (v1.62.0). `Cargo.lock` comes from the Walrus repo so dependency versions match.
