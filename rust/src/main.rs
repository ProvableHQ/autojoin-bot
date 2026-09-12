use anyhow::Result;
use autojoin_bot::{
    AleoNetwork, Config, DelegatedProverClient, KeySource, RecordStoreOptions, ScanResult,
    ScannerClient, credits_records, read_secure_key_file, write_record_store,
};
use snarkvm_circuit_network::{Aleo, AleoTestnetV0, AleoV0};
use snarkvm_console::{
    account::{PrivateKey, ViewKey},
    prelude::{MainnetV0, Network, TestnetV0},
};
use std::{collections::HashSet, time::Duration};
use tokio::time::{Instant, sleep};

async fn scan<N: Network>(
    config: &Config,
    scanner: &ScannerClient,
    view_key: &ViewKey<N>,
    uuid: &str,
) -> Result<ScanResult> {
    let records = scanner
        .fetch_unspent(
            view_key,
            uuid,
            config.start_block,
            config.record_program.as_deref(),
            config.record_name.as_deref(),
        )
        .await?;
    Ok(ScanResult {
        uuid: uuid.to_owned(),
        records,
    })
}

async fn run<N: Network, A: Aleo<Network = N>>(config: &Config) -> Result<(ScanResult, usize)> {
    let encoded = match &config.key_source {
        KeySource::ViewKey(path) | KeySource::PrivateKey(path) => read_secure_key_file(path)?,
    };
    let private_key = match &config.key_source {
        KeySource::PrivateKey(_) => Some(
            encoded
                .trim()
                .parse::<PrivateKey<N>>()
                .map_err(|error| anyhow::anyhow!("invalid private key in key file: {error}"))?,
        ),
        KeySource::ViewKey(_) => None,
    };
    let view_key = match &config.key_source {
        KeySource::ViewKey(_) => encoded
            .trim()
            .parse::<ViewKey<N>>()
            .map_err(|error| anyhow::anyhow!("invalid view key in key file: {error}"))?,
        KeySource::PrivateKey(_) => ViewKey::try_from(private_key.as_ref().expect("parsed above"))
            .map_err(|error| anyhow::anyhow!("failed to derive view key: {error}"))?,
    };
    let scanner = ScannerClient::new(config.endpoint());
    let uuid = scanner.register(&view_key, config.start_block).await?;
    let mut joins = 0;

    if config.autojoin_credits {
        let token = config
            .delegated_proving_token_file
            .as_deref()
            .map(read_secure_key_file)
            .transpose()?
            .map(|token| zeroize::Zeroizing::new(token.trim().to_owned()));
        let prover = DelegatedProverClient::new(
            config
                .delegated_proving_url
                .clone()
                .expect("validated configuration"),
            token,
        );
        loop {
            let records = scanner
                .fetch_unspent(
                    &view_key,
                    &uuid,
                    config.start_block,
                    Some("credits.aleo"),
                    Some("credits"),
                )
                .await?;
            let available = credits_records(&records)?;
            if available.len() <= 1 {
                break;
            }
            let count = available.len().min(16);
            let selected = &available[..count];
            let selected_tags: HashSet<String> = selected
                .iter()
                .filter_map(|record| record.tag.clone())
                .collect();
            let existing_tags: HashSet<String> = available
                .iter()
                .filter_map(|record| record.tag.clone())
                .collect();
            prover
                .prove_and_broadcast::<N, A>(
                    private_key.as_ref().expect("autojoin requires private key"),
                    config.network,
                    selected,
                )
                .await?;
            joins += 1;

            let deadline = Instant::now() + Duration::from_millis(config.autojoin_timeout_ms);
            loop {
                let current = scanner
                    .fetch_unspent(
                        &view_key,
                        &uuid,
                        config.start_block,
                        Some("credits.aleo"),
                        Some("credits"),
                    )
                    .await?;
                let current_credits = credits_records(&current)?;
                let inputs_gone = current_credits.iter().all(|record| {
                    record
                        .tag
                        .as_ref()
                        .is_none_or(|tag| !selected_tags.contains(tag))
                });
                let replacement_seen = current_credits.iter().any(|record| {
                    record
                        .tag
                        .as_ref()
                        .is_some_and(|tag| !existing_tags.contains(tag))
                });
                if inputs_gone && replacement_seen {
                    break;
                }
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "timed out waiting for autojoin transaction to reach the scanner"
                    );
                }
                sleep(Duration::from_millis(config.autojoin_poll_interval_ms)).await;
            }
        }
    }

    Ok((scan(config, &scanner, &view_key, &uuid).await?, joins))
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    let (result, joins) = match config.network {
        AleoNetwork::Mainnet => run::<MainnetV0, AleoV0>(&config).await?,
        AleoNetwork::Testnet => run::<TestnetV0, AleoTestnetV0>(&config).await?,
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
            "credits_joins": joins,
            "record_store": config.record_store_file,
            "decrypted_record_store": config.decrypted_record_store_file,
        }))?
    );
    Ok(())
}
