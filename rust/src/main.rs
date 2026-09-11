use anyhow::Result;
use autojoin_bot::{
    AleoNetwork, Config, KeySource, ScanResult, ScannerClient, read_secure_key_file,
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
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
