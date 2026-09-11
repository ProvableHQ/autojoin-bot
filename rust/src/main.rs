use anyhow::Result;
use autojoin_bot::{
    AleoNetwork, Config, KeySource, RecordStoreOptions, ScanResult, ScannerClient,
    read_secure_key_file, write_record_store,
};
use snarkvm_console::{
    account::{PrivateKey, ViewKey},
    prelude::{MainnetV0, Network, TestnetV0},
};

async fn run<N: Network>(config: &Config) -> Result<ScanResult> {
    let view_key = match &config.key_source {
        KeySource::ViewKey(path) => {
            let encoded = read_secure_key_file(path)?;
            encoded
                .trim()
                .parse::<ViewKey<N>>()
                .map_err(|error| anyhow::anyhow!("invalid view key in key file: {error}"))?
        }
        KeySource::PrivateKey(path) => {
            let encoded = read_secure_key_file(path)?;
            let private_key = encoded
                .trim()
                .parse::<PrivateKey<N>>()
                .map_err(|error| anyhow::anyhow!("invalid private key in key file: {error}"))?;
            ViewKey::try_from(private_key)
                .map_err(|error| anyhow::anyhow!("failed to derive view key: {error}"))?
        }
    };
    let scanner = ScannerClient::new(config.endpoint());
    let uuid = scanner.register(&view_key, config.start_block).await?;
    let records = scanner
        .fetch_unspent(
            &view_key,
            &uuid,
            config.start_block,
            config.record_program.as_deref(),
            config.record_name.as_deref(),
        )
        .await?;
    Ok(ScanResult { uuid, records })
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    let result = match config.network {
        AleoNetwork::Mainnet => run::<MainnetV0>(&config).await?,
        AleoNetwork::Testnet => run::<TestnetV0>(&config).await?,
    };
    write_record_store(
        &config.record_store_file,
        config.network,
        &result.uuid,
        &result.records,
        RecordStoreOptions {
            secure: config.record_store_private,
            include_plaintext: false,
        },
    )?;
    if let Some(path) = &config.decrypted_record_store_file {
        write_record_store(
            path,
            config.network,
            &result.uuid,
            &result.records,
            RecordStoreOptions {
                secure: true,
                include_plaintext: true,
            },
        )?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "network": config.network.as_str(),
            "uuid": result.uuid,
            "record_count": result.records.len(),
            "record_store": config.record_store_file,
            "decrypted_record_store": config.decrypted_record_store_file,
        }))?
    );
    Ok(())
}
