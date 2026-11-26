//! Walrus access through the Walrus Rust SDK (`walrus-sdk`).

use std::path::Path;

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

/// Uploads `ciphertext` and returns its blob ID.
pub async fn store(
    ciphertext: &[u8],
    context: &str,
    epochs: u32,
    config_path: Option<&Path>,
) -> Result<String> {
    let client = contract_client(config_path, context).await?;

    let args = StoreArgs::default_with_epochs(epochs);
    let results = client
        .reserve_and_store_blobs(vec![ciphertext.to_vec()], &args)
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
