//! The on-disk key store: `~/.brine/<blob-id>/`, owner-only permissions.
//!
//! Set `BRINE_HOME` to use a different directory than `~/.brine`.

use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, Write},
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

/// Reads a passphrase from `path`, or from stdin when `path` is `-`.
///
/// Only the first line is used, without its line ending. On Unix a file that group or others can
/// access is refused, like `ssh` does for private keys.
pub fn read_passphrase_file(path: &Path) -> Result<SecretString> {
    let text = if path == Path::new("-") {
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .context("cannot read the passphrase from stdin")?;
        line
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .with_context(|| format!("cannot read {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                bail!(
                    "{} is accessible by other users (mode {:o}); run `chmod 600` on it",
                    path.display(),
                    mode & 0o777
                );
            }
        }
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?
    };
    first_line_passphrase(&text)
}

/// Takes the first line of `text` as the passphrase. Rejects an empty one.
fn first_line_passphrase(text: &str) -> Result<SecretString> {
    let line = text.lines().next().unwrap_or("");
    if line.is_empty() {
        bail!("the passphrase must not be empty");
    }
    Ok(line.to_owned().into())
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

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("brine-ks-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_with_mode(path: &Path, text: &str, mode: u32) {
        fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn passphrase_file_uses_first_line_without_line_ending() {
        let dir = scratch("first_line");
        for (name, text) in [
            ("lf", "hunter 2\nignored\n"),
            ("crlf", "hunter 2\r\n"),
            ("bare", "hunter 2"),
        ] {
            let path = dir.join(name);
            write_with_mode(&path, text, 0o600);
            let pass = read_passphrase_file(&path).unwrap();
            assert_eq!(pass.expose_secret(), "hunter 2", "{name}");
        }
    }

    #[test]
    fn passphrase_file_rejects_empty() {
        let dir = scratch("empty");
        for (name, text) in [("zero", ""), ("newline", "\n")] {
            let path = dir.join(name);
            write_with_mode(&path, text, 0o600);
            assert!(read_passphrase_file(&path).is_err(), "{name}");
        }
    }

    #[test]
    fn passphrase_file_missing_is_an_error() {
        let dir = scratch("missing");
        assert!(read_passphrase_file(&dir.join("nope")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn passphrase_file_rejects_group_or_world_access() {
        let dir = scratch("perms");
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666] {
            let path = dir.join(format!("p{mode:o}"));
            write_with_mode(&path, "secret\n", mode);
            let error = read_passphrase_file(&path).unwrap_err().to_string();
            assert!(
                error.contains("accessible by other users"),
                "{mode:o}: {error}"
            );
        }
        let ok = dir.join("ok");
        write_with_mode(&ok, "secret\n", 0o400);
        assert!(read_passphrase_file(&ok).is_ok());
    }
}
