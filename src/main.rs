//! brine: encrypt a file to one or more age recipients, then store it on Walrus.
//!
//! * `brine store` encrypts the file to a newly generated age key, or to the `--recipient` public
//!   keys you give it, uploads the ciphertext to Walrus, and moves the passphrase-protected
//!   private key (if one was generated) into `~/.brine/<blob-id>/`.
//! * `brine fetch` reads the blob back from Walrus and decrypts it with that key.

mod keystore;
mod vault;
mod walrus;

use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

/// Default Walrus network when `--context` is not given.
const DEFAULT_CONTEXT: &str = "mainnet";
/// Default number of epochs to pay for when `--epochs` is not given.
const DEFAULT_EPOCHS: u32 = 5;

#[derive(Parser)]
#[command(name = "brine", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file, upload it to Walrus, and save the key files under ~/.brine/<blob-id>/
    Store {
        /// File to encrypt and upload
        file: PathBuf,
        /// Encrypt to an existing public key (`age1...`) instead of generating a new key; can be
        /// repeated. Without any --recipient, one new key is generated and saved.
        #[arg(long = "recipient")]
        recipients: Vec<String>,
        /// Walrus network context from the client config (for example `testnet`)
        #[arg(long, default_value = DEFAULT_CONTEXT)]
        context: String,
        /// Number of Walrus epochs to store the blob for
        #[arg(long, default_value_t = DEFAULT_EPOCHS)]
        epochs: u32,
        /// Upload without asking for confirmation
        #[arg(long)]
        do_it: bool,
        /// Read the new key passphrase from this file (`-` for stdin) instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Path to a Walrus client config (default: the standard locations, then built-in)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Delete a blob you stored from Walrus (frees its storage; local keys are kept)
    Wipe {
        /// Walrus blob ID
        blob_id: String,
        /// Walrus network context from the client config (for example `testnet`)
        #[arg(long, default_value = DEFAULT_CONTEXT)]
        context: String,
        /// Delete without asking for confirmation
        #[arg(long)]
        do_it: bool,
        /// Path to a Walrus client config (default: the standard locations, then built-in)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Download a blob from Walrus and decrypt it to --out
    Fetch {
        /// Walrus blob ID
        blob_id: String,
        /// Where to write the decrypted file (must not already exist)
        #[arg(long)]
        out: PathBuf,
        /// Walrus network context from the client config (for example `testnet`)
        #[arg(long, default_value = DEFAULT_CONTEXT)]
        context: String,
        /// Key file to use instead of the ones in ~/.brine/<blob-id>/ (can be repeated)
        #[arg(long = "key")]
        keys: Vec<PathBuf>,
        /// Read the passphrase from this file (`-` for stdin) instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Path to a Walrus client config (default: the standard locations, then built-in)
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(io::stderr)
        .init();

    match Cli::parse().command {
        Command::Store {
            file,
            recipients,
            context,
            epochs,
            do_it,
            passphrase_file,
            config,
        } => {
            let options = StoreOptions {
                context,
                epochs,
                do_it,
                passphrase_file,
                config,
            };
            store(file, recipients, options).await
        }
        Command::Wipe {
            blob_id,
            context,
            do_it,
            config,
        } => wipe(&blob_id, &context, do_it, config).await,
        Command::Fetch {
            blob_id,
            out,
            context,
            keys,
            passphrase_file,
            config,
        } => fetch(&blob_id, out, &context, keys, passphrase_file, config).await,
    }
}

struct StoreOptions {
    context: String,
    epochs: u32,
    do_it: bool,
    passphrase_file: Option<PathBuf>,
    config: Option<PathBuf>,
}

async fn store(file: PathBuf, recipients: Vec<String>, options: StoreOptions) -> Result<()> {
    let StoreOptions {
        context,
        epochs,
        do_it,
        passphrase_file,
        config: config_path,
    } = options;
    let context = context.as_str();
    if epochs == 0 {
        bail!("--epochs must be at least 1");
    }
    let plaintext =
        std::fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
    if plaintext.is_empty() {
        bail!("{} is empty; nothing to store", file.display());
    }

    let supplied = recipients
        .iter()
        .map(|text| vault::parse_recipient(text))
        .collect::<Result<Vec<_>>>()?;
    // Without --recipient, one new key is generated; with it, only the given keys are used.
    let generate = supplied.is_empty();
    // A passphrase is only needed to protect a newly generated private key.
    let passphrase = if !generate {
        if passphrase_file.is_some() {
            bail!("--passphrase-file only applies when a new key is generated (no --recipient)");
        }
        None
    } else if let Some(path) = &passphrase_file {
        Some(keystore::read_passphrase_file(path)?)
    } else {
        Some(keystore::prompt_new_passphrase()?)
    };

    eprintln!("encrypting...");
    let bundle = vault::seal(
        &plaintext,
        usize::from(generate),
        &supplied,
        passphrase.as_ref(),
    )?;
    drop(plaintext);

    // The key files go to disk *before* the upload. Whatever happens next, the ciphertext can
    // never exist on Walrus without the keys that open it being saved somewhere.
    let staging = keystore::stage(&bundle)?;

    if !do_it && let Err(error) = confirm(&file, &bundle, context, epochs) {
        keystore::discard(&staging);
        return Err(error);
    }

    let stored = walrus::store(&bundle.ciphertext, context, epochs, config_path.as_deref()).await;
    let blob_id = match stored {
        Ok(blob_id) => blob_id,
        Err(error) => {
            keystore::discard(&staging);
            return Err(error.context("upload to Walrus failed; no key files were kept"));
        }
    };

    let final_dir = keystore::commit(staging, &blob_id)?;
    println!("blob id: {blob_id}");
    if generate {
        println!("key:     moved to {}", final_dir.display());
    } else {
        println!(
            "key:     none generated; recipients saved in {}",
            final_dir.display()
        );
    }
    println!("fetch:   brine fetch {blob_id} --context {context} --out <file>");
    Ok(())
}

async fn wipe(
    blob_id: &str,
    context: &str,
    do_it: bool,
    config_path: Option<PathBuf>,
) -> Result<()> {
    if !do_it {
        eprintln!();
        eprintln!("WARNING: about to delete blob {blob_id} from Walrus ({context})");
        eprintln!();
        eprintln!("  * Only deletable blobs owned by your Sui wallet can be deleted.");
        eprintln!("  * This costs SUI (gas) and frees the blob's storage for reuse.");
        eprintln!("  * It does not recall copies. Anyone who already downloaded the ciphertext");
        eprintln!("    keeps it, and storage nodes may serve it until they clean it up.");
        eprintln!("  * Local keys in ~/.brine/{blob_id}/ are NOT removed.");
        eprintln!();
        confirm_yes("delete? [y/N] ", "aborted; nothing was deleted")?;
    }
    let deleted = walrus::delete(blob_id, context, config_path.as_deref()).await?;
    if deleted == 0 {
        bail!(
            "no deletable blob {blob_id} is owned by this wallet on {context} \
             (wrong network, wrong wallet, already deleted or expired, or stored as permanent)"
        );
    }
    println!("deleted {deleted} blob object(s) for {blob_id}");
    Ok(())
}

async fn fetch(
    blob_id: &str,
    out: PathBuf,
    context: &str,
    key_files: Vec<PathBuf>,
    passphrase_file: Option<PathBuf>,
    config_path: Option<PathBuf>,
) -> Result<()> {
    if out.exists() {
        bail!("{} already exists; refusing to overwrite", out.display());
    }
    let key_files = if key_files.is_empty() {
        keystore::keys_for(blob_id)?
    } else {
        key_files
    };
    let passphrase = match &passphrase_file {
        Some(path) => keystore::read_passphrase_file(path)?,
        None => rpassword::prompt_password("passphrase: ")
            .context("cannot read passphrase")?
            .into(),
    };

    eprintln!("reading blob {blob_id} from Walrus ({context})...");
    let ciphertext = walrus::fetch(blob_id, context, config_path.as_deref()).await?;

    eprintln!("decrypting...");
    let plaintext = vault::open(&ciphertext, &key_files, &passphrase)?;
    keystore::write_private_file(&out, &plaintext)?;
    println!("wrote {} bytes to {}", plaintext.len(), out.display());
    Ok(())
}

/// Prints what is about to happen and asks for a yes. Fails unless the answer is yes.
fn confirm(
    file: &std::path::Path,
    bundle: &vault::Bundle,
    context: &str,
    epochs: u32,
) -> Result<()> {
    eprintln!();
    eprintln!("WARNING: about to upload to Walrus ({context})");
    eprintln!("  file:       {}", file.display());
    eprintln!(
        "  uploading:  {} bytes of age ciphertext",
        bundle.ciphertext.len()
    );
    eprintln!(
        "  recipients: {} (any one can decrypt; {} new key file(s))",
        bundle.recipients.lines().count(),
        bundle.keys.len()
    );
    eprintln!("  stored for: {epochs} epoch(s)");
    eprintln!();
    eprintln!("  * This spends SUI (gas) and WAL (storage) from your Sui wallet.");
    eprintln!("  * The ciphertext becomes public; anyone can download and keep a copy.");
    eprintln!("  * Only the recipients' private keys can decrypt it. Lose them (and the");
    eprintln!("    passphrase for new key files) and the data is gone. New key files will be");
    eprintln!("    moved to ~/.brine/<blob-id>/.");
    eprintln!();
    confirm_yes("upload? [y/N] ", "aborted; nothing was uploaded")
}

/// Asks a yes/no question on the terminal. Fails unless the answer is yes.
fn confirm_yes(question: &str, refusal: &str) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("not an interactive terminal; pass --do-it to skip the confirmation");
    }
    eprint!("{question}");
    io::stderr().flush().ok();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        Ok(())
    } else {
        bail!("{refusal}")
    }
}
