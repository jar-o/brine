//! Walrus access through the Walrus Rust SDK (`walrus-sdk`).

use std::path::Path;

use crate::vault::Ciphertext;
use age::Decryptor;
use anyhow::{Context, Result, anyhow, bail};
use walrus_sdk::{
    config::{
        ClientConfig, default_configuration_for_rpc_url, default_configuration_paths,
        load_configuration,
    },
    core::{BlobId, encoding::Primary},
    node_client::{StoreArgs, StoreBlobsApi as _, WalrusNodeClient},
    sui::{
        client::{SuiContractClient, retry_client::RetriableSuiClient},
        config::WalletConfig,
    },
};

/// Loads the client config for `context`.
///
/// Uses `config_path` if given, then the standard Walrus config locations. If no config file
/// exists anywhere, the SDK's built-in mainnet/testnet configuration is used.
fn load_config(config_path: Option<&Path>, context: &str) -> Result<ClientConfig> {
    match load_configuration(config_path, Some(context)) {
        Ok(config) => Ok(config),
        Err(error) => {
            let no_config_file = config_path.is_none()
                && !default_configuration_paths()
                    .iter()
                    .any(|path| path.exists());
            if no_config_file
                && let Some((config, _)) =
                    default_configuration_for_rpc_url(&format!("https://fullnode.{context}.sui.io"))
            {
                return Ok(config);
            }
            Err(error.context(format!(
                "cannot load the Walrus config for context `{context}`; \
                 pass --config or put client_config.yaml in ~/.config/walrus/"
            )))
        }
    }
}

/// Builds a client that can send transactions from the local Sui wallet.
async fn contract_client(
    config_path: Option<&Path>,
    context: &str,
) -> Result<WalrusNodeClient<SuiContractClient>> {
    let config = load_config(config_path, context)?;
    let wallet = WalletConfig::load_wallet(
        config.wallet_config.as_ref(),
        config.communication_config.sui_client_request_timeout,
    )
    .context("cannot load the Sui wallet (is `sui client` set up for this network?)")?;

    let sui_client = config.new_contract_client(wallet, None).await?;
    let refresher = config
        .build_refresher_and_run(sui_client.read_client().clone())
        .await?;
    Ok(WalrusNodeClient::new_contract_client(
        config, refresher, sui_client,
    )?)
}

/// Parses a blob ID.
fn parse_blob_id(blob_id: &str) -> Result<BlobId> {
    blob_id
        .parse()
        .map_err(|error| anyhow!("invalid blob id `{blob_id}`: {error}"))
}

/// Fails unless `bytes` start with a well-formed age header.
///
/// Last line of defence before an upload: `store` takes a [`Ciphertext`], which only encryption
/// can produce, and this check makes sure that what it holds really is an age file.
fn ensure_age_ciphertext(bytes: &[u8]) -> Result<()> {
    Decryptor::new_buffered(bytes).map(drop).map_err(|error| {
        anyhow!("refusing to upload: the data is not an age-encrypted file ({error})")
    })
}

/// Uploads `ciphertext` and returns its blob ID.
///
/// Refuses, before touching the config, the wallet or the network, anything that is not age
/// ciphertext.
pub async fn store(
    ciphertext: &Ciphertext,
    context: &str,
    epochs: u32,
    config_path: Option<&Path>,
) -> Result<String> {
    ensure_age_ciphertext(ciphertext.as_bytes())?;
    let client = contract_client(config_path, context).await?;

    let args = StoreArgs::default_with_epochs(epochs);
    let results = client
        .reserve_and_store_blobs(vec![ciphertext.as_bytes().to_vec()], &args)
        .await?;
    let result = results
        .first()
        .ok_or_else(|| anyhow!("Walrus returned no result"))?;
    match result.blob_id() {
        Some(blob_id) => Ok(blob_id.to_string()),
        None => bail!("the blob was not stored: {result:?}"),
    }
}

/// Downloads the blob with the given ID.
pub async fn fetch(blob_id: &str, context: &str, config_path: Option<&Path>) -> Result<Vec<u8>> {
    let blob_id = parse_blob_id(blob_id)?;
    let config = load_config(config_path, context)?;

    let rpc_urls = if config.rpc_urls.is_empty() {
        vec![format!("https://fullnode.{context}.sui.io:443")]
    } else {
        config.rpc_urls.clone()
    };
    let sui_client =
        RetriableSuiClient::new_for_rpc_urls(&rpc_urls, config.backoff_config().clone())
            .context("cannot connect to a Sui RPC node")?;
    let read_client = config.new_read_client(sui_client).await?;
    let client = WalrusNodeClient::new_read_client_with_refresher(config, read_client).await?;

    Ok(client.read_blob::<Primary>(&blob_id).await?)
}

/// Deletes the deletable blobs with this ID that the wallet owns, and returns how many.
pub async fn delete(blob_id: &str, context: &str, config_path: Option<&Path>) -> Result<usize> {
    let blob_id = parse_blob_id(blob_id)?;
    let client = contract_client(config_path, context).await?;
    Ok(client.delete_owned_blob(&blob_id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault;

    /// Things that must never reach Walrus: ordinary text, binary formats, near-misses of the age
    /// header, and empty input.
    fn cleartext_samples() -> Vec<Vec<u8>> {
        vec![
            b"my secret notes".to_vec(),
            b"".to_vec(),
            b"\x89PNG\r\n\x1a\n....".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n".to_vec(),
            b"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ".to_vec(),
            b"age-encryption.org/v1".to_vec(),
            b"age-encryption.org/v1\n".to_vec(),
            b"age-encryption.org/v1\n-> X25519 AAAA\nBBBB\n".to_vec(),
            b"age-encryption.org/v2\n--- AAAA\n".to_vec(),
            vec![0u8; 1024],
        ]
    }

    #[test]
    fn guard_rejects_cleartext() {
        for sample in cleartext_samples() {
            let error = ensure_age_ciphertext(&sample).unwrap_err().to_string();
            assert!(error.contains("refusing to upload"), "{sample:?}: {error}");
        }
    }

    #[test]
    fn guard_accepts_what_seal_produces() {
        for plaintext in cleartext_samples().iter().filter(|p| !p.is_empty()) {
            let key = age::x25519::Identity::generate().to_public();
            let bundle = vault::seal(plaintext, 0, &[key], None).unwrap();
            ensure_age_ciphertext(bundle.ciphertext.as_bytes()).unwrap();
        }
    }

    #[test]
    fn sealed_output_never_contains_the_plaintext() {
        let marker = b"PLAINTEXT-MARKER-0123456789-do-not-leak";
        let mut plaintext = marker.repeat(50);
        plaintext.extend_from_slice(b"tail");
        let key = age::x25519::Identity::generate().to_public();
        let bundle = vault::seal(&plaintext, 0, &[key], None).unwrap();
        let found = bundle
            .ciphertext
            .as_bytes()
            .windows(marker.len())
            .any(|window| window == marker);
        assert!(!found, "plaintext appears inside the ciphertext");
    }

    /// The real upload function refuses cleartext before it loads any config, opens the wallet
    /// or touches the network. The config path below does not exist: if the guard ran later,
    /// the error would be about the config instead.
    #[tokio::test]
    async fn store_refuses_cleartext_before_any_network_or_wallet_access() {
        let missing = Path::new("/nonexistent/brine-test/client_config.yaml");
        for sample in cleartext_samples() {
            let cleartext = Ciphertext::unchecked_for_test(&sample);
            let error = store(&cleartext, "testnet", 1, Some(missing))
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("refusing to upload"), "{sample:?}: {error}");
        }
    }

    /// For real ciphertext the guard passes and the upload moves on to the config, which
    /// fails here because the file is missing. So the refusal above is not a blanket failure.
    #[tokio::test]
    async fn store_lets_real_ciphertext_past_the_guard() {
        let missing = Path::new("/nonexistent/brine-test/client_config.yaml");
        let key = age::x25519::Identity::generate().to_public();
        let bundle = vault::seal(b"hello", 0, &[key], None).unwrap();
        let error = store(&bundle.ciphertext, "testnet", 1, Some(missing))
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("refusing to upload"), "{error}");
    }
}
