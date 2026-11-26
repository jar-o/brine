//! age encryption: one X25519 key pair per recipient, private keys wrapped with one passphrase.

use std::{
    io::{Read, Write},
    iter,
    path::PathBuf,
    str::FromStr,
};

use age::{
    DecryptError, Decryptor, Encryptor, Identity, Recipient,
    secrecy::{ExposeSecret, SecretString},
    x25519,
};
use anyhow::{Context, Result, bail};

/// Everything produced by [`seal`].
pub struct Bundle {
    /// The age file for the plaintext, encrypted to every recipient.
    pub ciphertext: Vec<u8>,
    /// One passphrase-protected private key per recipient, as `(file name, age file bytes)`.
    pub keys: Vec<(String, Vec<u8>)>,
    /// The public keys, one per line.
    pub recipients: String,
}

/// Parses a public age recipient (`age1...`).
pub fn parse_recipient(text: &str) -> Result<x25519::Recipient> {
    x25519::Recipient::from_str(text.trim())
        .map_err(|error| anyhow::anyhow!("invalid recipient `{text}`: {error}"))
}

/// Encrypts `plaintext` to `count` freshly generated recipients plus the `supplied` public keys.
///
/// Private keys are generated (and wrapped with `passphrase`) only for the new recipients, so the
/// passphrase is required exactly when `count > 0`.
pub fn seal(
    plaintext: &[u8],
    count: usize,
    supplied: &[x25519::Recipient],
    passphrase: Option<&SecretString>,
) -> Result<Bundle> {
    let identities: Vec<x25519::Identity> =
        (0..count).map(|_| x25519::Identity::generate()).collect();
    let mut recipients: Vec<x25519::Recipient> =
        identities.iter().map(|id| id.to_public()).collect();
    recipients.extend(supplied.iter().cloned());
    if recipients.is_empty() {
        bail!("no recipients: generate a key with --keys or pass --recipient");
    }

    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn Recipient))
        .context("cannot set up encryption")?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(plaintext)?;
    writer.finish()?;

    let mut keys = Vec::with_capacity(count);
    for (index, identity) in identities.iter().enumerate() {
        let passphrase = passphrase.context("a passphrase is required to protect new keys")?;
        keys.push((
            format!("key-{}.age", index + 1),
            wrap_identity(identity, passphrase)?,
        ));
    }
    let recipients = recipients.iter().map(|r| format!("{r}\n")).collect();
    Ok(Bundle {
        ciphertext,
        keys,
        recipients,
    })
}

/// Decrypts `ciphertext` with the first key file that the passphrase opens and that matches.
pub fn open(
    ciphertext: &[u8],
    key_files: &[PathBuf],
    passphrase: &SecretString,
) -> Result<Vec<u8>> {
    let mut opened_any = false;
    for path in key_files {
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let identity = match unwrap_identity(&bytes, passphrase) {
            Ok(identity) => identity,
            Err(error) => {
                eprintln!("skipping {}: {error}", path.display());
                continue;
            }
        };
        opened_any = true;
        let decryptor = Decryptor::new_buffered(ciphertext).context("not a valid age file")?;
        match decryptor.decrypt(iter::once(&identity as &dyn Identity)) {
            Ok(mut reader) => {
                let mut plaintext = Vec::new();
                reader
                    .read_to_end(&mut plaintext)
                    .context("decryption failed (corrupt data)")?;
                return Ok(plaintext);
            }
            Err(DecryptError::NoMatchingKeys) => {
                eprintln!("{} is not a recipient of this blob", path.display());
            }
            Err(error) => return Err(error).context("decryption failed"),
        }
    }
    if opened_any {
        bail!("none of the unlocked keys can decrypt this blob");
    }
    bail!("no key file could be unlocked: wrong passphrase, or not brine key files")
}

fn wrap_identity(identity: &x25519::Identity, passphrase: &SecretString) -> Result<Vec<u8>> {
    let encryptor = Encryptor::with_user_passphrase(passphrase.clone());
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(identity.to_string().expose_secret().as_bytes())?;
    writer.write_all(b"\n")?;
    writer.finish()?;
    Ok(out)
}

fn unwrap_identity(bytes: &[u8], passphrase: &SecretString) -> Result<x25519::Identity> {
    let decryptor = Decryptor::new_buffered(bytes).context("not an age file")?;
    if !decryptor.is_scrypt() {
        bail!("not a passphrase-protected key file");
    }
    let unlock = age::scrypt::Identity::new(passphrase.clone());
    let mut reader = decryptor
        .decrypt(iter::once(&unlock as &dyn Identity))
        .map_err(|_| anyhow::anyhow!("wrong passphrase"))?;
    let mut text = String::new();
    reader
        .read_to_string(&mut text)
        .context("corrupt key file")?;
    x25519::Identity::from_str(text.trim()).map_err(|e| anyhow::anyhow!("corrupt key file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_keys(dir: &std::path::Path, bundle: &Bundle) -> Vec<PathBuf> {
        bundle
            .keys
            .iter()
            .map(|(name, bytes)| {
                let path = dir.join(name);
                std::fs::write(&path, bytes).unwrap();
                path
            })
            .collect()
    }

    #[test]
    fn any_single_key_decrypts() {
        let pass = SecretString::from("correct horse".to_owned());
        let bundle = seal(b"top secret", 3, &[], Some(&pass)).unwrap();
        let dir = tempdir("any_single_key");
        let files = write_keys(&dir, &bundle);
        assert_eq!(files.len(), 3);
        for file in &files {
            let out = open(&bundle.ciphertext, std::slice::from_ref(file), &pass).unwrap();
            assert_eq!(out, b"top secret");
        }
        assert_ne!(bundle.ciphertext, b"top secret");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let pass = SecretString::from("right".to_owned());
        let bundle = seal(b"data", 1, &[], Some(&pass)).unwrap();
        let dir = tempdir("wrong_passphrase");
        let files = write_keys(&dir, &bundle);
        let wrong = SecretString::from("wrong".to_owned());
        assert!(open(&bundle.ciphertext, &files, &wrong).is_err());
    }

    #[test]
    fn key_from_another_blob_fails() {
        let pass = SecretString::from("p".to_owned());
        let one = seal(b"one", 1, &[], Some(&pass)).unwrap();
        let two = seal(b"two", 1, &[], Some(&pass)).unwrap();
        let dir = tempdir("other_blob");
        let files = write_keys(&dir, &two);
        assert!(open(&one.ciphertext, &files, &pass).is_err());
    }

    #[test]
    fn supplied_recipient_decrypts_without_a_generated_key() {
        let pass = SecretString::from("p".to_owned());
        let outside = x25519::Identity::generate();
        let bundle = seal(b"hello", 0, &[outside.to_public()], None).unwrap();
        assert!(bundle.keys.is_empty());
        let decryptor = Decryptor::new_buffered(&bundle.ciphertext[..]).unwrap();
        let mut reader = decryptor
            .decrypt(iter::once(&outside as &dyn Identity))
            .unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello");
        // New keys without a passphrase, and no recipients at all, are both rejected.
        assert!(seal(b"x", 1, &[], None).is_err());
        assert!(seal(b"x", 0, &[], Some(&pass)).is_err());
    }

    #[test]
    fn each_of_multiple_supplied_recipients_decrypts() {
        let first = x25519::Identity::generate();
        let second = x25519::Identity::generate();
        let stranger = x25519::Identity::generate();
        let bundle = seal(b"shared", 0, &[first.to_public(), second.to_public()], None).unwrap();
        assert!(bundle.keys.is_empty());
        assert_eq!(bundle.recipients.lines().count(), 2);
        for identity in [&first, &second] {
            let decryptor = Decryptor::new_buffered(&bundle.ciphertext[..]).unwrap();
            let mut reader = decryptor
                .decrypt(iter::once(identity as &dyn Identity))
                .unwrap();
            let mut out = Vec::new();
            reader.read_to_end(&mut out).unwrap();
            assert_eq!(out, b"shared");
        }
        let decryptor = Decryptor::new_buffered(&bundle.ciphertext[..]).unwrap();
        assert!(
            decryptor
                .decrypt(iter::once(&stranger as &dyn Identity))
                .is_err()
        );
    }

    #[test]
    fn rejects_malformed_recipient() {
        assert!(parse_recipient("not-a-key").is_err());
        let good = x25519::Identity::generate().to_public().to_string();
        assert!(parse_recipient(&good).is_ok());
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("brine-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
