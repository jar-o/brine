//! The on-disk key store: `~/.brine/<blob-id>/`, owner-only permissions.
//!
//! Set `BRINE_HOME` to use a different directory than `~/.brine`.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};

use crate::vault::Bundle;

/// The root of the key store.
fn root() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("BRINE_HOME") {
        return Ok(PathBuf::from(dir));
    }
    Ok(home::home_dir()
        .context("cannot determine the home directory; set BRINE_HOME")?
        .join(".brine"))
}

/// Asks for a new passphrase twice.
pub fn prompt_new_passphrase() -> Result<SecretString> {
    let first = rpassword::prompt_password("new passphrase for the key files: ")
        .context("cannot read passphrase")?;
    if first.is_empty() {
        bail!("the passphrase must not be empty");
    }
    let second =
        rpassword::prompt_password("repeat passphrase: ").context("cannot read passphrase")?;
    if first != second {
        bail!("the passphrases do not match");
    }
    Ok(first.into())
}

/// Writes the key files to a hidden staging directory inside the key store.
pub fn stage(bundle: &Bundle) -> Result<PathBuf> {
    let root = root()?;
    create_private_dir(&root)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let staging = root.join(format!(".pending-{}-{nanos}", std::process::id()));
    create_private_dir(&staging)?;
    for (name, bytes) in &bundle.keys {
        write_private_file(&staging.join(name), bytes)?;
    }
    write_private_file(
        &staging.join("recipients.txt"),
        bundle.recipients.as_bytes(),
    )?;
    Ok(staging)
}

/// Removes a staging directory (best effort).
pub fn discard(staging: &Path) {
    if let Err(error) = fs::remove_dir_all(staging) {
        eprintln!("warning: could not remove {}: {error}", staging.display());
    }
}

/// Renames the staging directory to `<root>/<blob-id>`.
///
/// On failure the staging directory is left in place and its path is reported, because by this
/// point the blob is already uploaded and these are the only keys.
pub fn commit(staging: PathBuf, blob_id: &str) -> Result<PathBuf> {
    let target = root()?.join(blob_id);
    if target.exists() {
        bail!(
            "{} already exists. The blob was uploaded; its NEW keys are still in {}",
            target.display(),
            staging.display()
        );
    }
    fs::rename(&staging, &target).with_context(|| {
        format!(
            "could not move the keys to {}. The blob was uploaded; its keys are still in {}",
            target.display(),
            staging.display()
        )
    })?;
    Ok(target)
}

/// Lists the key files saved for a blob.
pub fn keys_for(blob_id: &str) -> Result<Vec<PathBuf>> {
    // The blob ID becomes a path component, so keep it to the URL-safe base64 alphabet.
    if blob_id.is_empty()
        || !blob_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid blob id: {blob_id}");
    }
    let dir = root()?.join(blob_id);
    let entries = fs::read_dir(&dir).with_context(|| {
        format!(
            "no keys found in {}; pass the key files with --key <file>",
            dir.display()
        )
    })?;
    let mut keys: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "age"))
        .collect();
    keys.sort();
    if keys.is_empty() {
        bail!(
            "no *.age key files in {}; pass them with --key <file>",
            dir.display()
        );
    }
    Ok(keys)
}

/// Creates a new file readable only by the owner. Refuses to overwrite.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(path)
        .with_context(|| format!("cannot create {}", path.display()))
}
