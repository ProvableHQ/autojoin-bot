use anyhow::{Context, Result};
use autojoin_bot::{
    AleoNetwork, Config, DelegatedProverClient, KeySource, RecordFamily, RecordStoreOptions,
    ScanResult, ScannerClient, read_secure_key_file, records_for_family, write_record_store,
};
use snarkvm_circuit_network::{Aleo, AleoTestnetV0, AleoV0};
use snarkvm_console::{
    account::{PrivateKey, ViewKey},
    prelude::{MainnetV0, Network, TestnetV0},
};
use std::{collections::HashSet, time::Duration};
use tokio::time::{Instant, sleep};

#[derive(Default)]
struct JoinCounts {
    credits: usize,
    usdcx: usize,
    arc20_eth: usize,
    arc20_sol: usize,
    arc20_wbtc: usize,
}

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

async fn run<N: Network, A: Aleo<Network = N>>(
    config: &Config,
) -> Result<(ScanResult, JoinCounts)> {
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
    let scanner = ScannerClient::new(
        config.endpoint(),
        Duration::from_millis(config.scan_sync_poll_interval_ms),
        Duration::from_millis(config.scan_sync_timeout_ms),
    );
    let uuid = scanner.ensure_ready(&view_key, config.start_block).await?;
    let mut join_counts = JoinCounts::default();

    let families = [
        (RecordFamily::Credits, config.autojoin_credits),
        (RecordFamily::Usdcx, config.autojoin_usdcx),
        (RecordFamily::Arc20Eth, config.autojoin_arc20_eth),
        (RecordFamily::Arc20Sol, config.autojoin_arc20_sol),
        (RecordFamily::Arc20Wbtc, config.autojoin_arc20_wbtc),
    ];
    if families.iter().any(|(_, enabled)| *enabled) {
        let prover = DelegatedProverClient::new(config.delegated_proving_url.clone());
        for (family, enabled) in families {
            if !enabled {
                continue;
            }
            let joins = consolidate_family::<N, A>(
                config,
                &scanner,
                &prover,
                private_key.as_ref().expect("autojoin requires private key"),
                &view_key,
                &uuid,
                family,
            )
            .await?;
            match family {
                RecordFamily::Credits => join_counts.credits = joins,
                RecordFamily::Usdcx => join_counts.usdcx = joins,
                RecordFamily::Arc20Eth => join_counts.arc20_eth = joins,
                RecordFamily::Arc20Sol => join_counts.arc20_sol = joins,
                RecordFamily::Arc20Wbtc => join_counts.arc20_wbtc = joins,
            }
        }
    }

    Ok((scan(config, &scanner, &view_key, &uuid).await?, join_counts))
}

#[allow(clippy::too_many_arguments)]
async fn consolidate_family<N: Network, A: Aleo<Network = N>>(
    config: &Config,
    scanner: &ScannerClient,
    prover: &DelegatedProverClient,
    private_key: &PrivateKey<N>,
    view_key: &ViewKey<N>,
    uuid: &str,
    family: RecordFamily,
) -> Result<usize> {
    let mut joins = 0;
    let record_program = family
        .record_program(config.network)
        .context("record family is not configured for this network")?;
    loop {
        let records = scanner
            .fetch_unspent(
                view_key,
                uuid,
                config.start_block,
                Some(record_program),
                Some(family.record_name()),
            )
            .await?;
        let available = records_for_family(&records, family, config.network)?;
        if available.len() <= 1 {
            return Ok(joins);
        }
        let count = available.len().min(family.max_batch());
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
            .prove_and_broadcast::<N, A>(private_key, config.network, family, selected)
            .await?;
        joins += 1;

        let deadline = Instant::now() + Duration::from_millis(config.autojoin_timeout_ms);
        loop {
            let current = scanner
                .fetch_unspent(
                    view_key,
                    uuid,
                    config.start_block,
                    Some(record_program),
                    Some(family.record_name()),
                )
                .await?;
            let current_records = records_for_family(&current, family, config.network)?;
            let inputs_gone = current_records.iter().all(|record| {
                record
                    .tag
                    .as_ref()
                    .is_none_or(|tag| !selected_tags.contains(tag))
            });
            let replacement_seen = current_records.iter().any(|record| {
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
                    "timed out waiting for {} autojoin transaction to reach the scanner",
                    family.name()
                );
            }
            sleep(Duration::from_millis(config.autojoin_poll_interval_ms)).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    let (result, join_counts) = match config.network {
        AleoNetwork::Mainnet => run::<MainnetV0, AleoV0>(&config).await?,
        AleoNetwork::Testnet => run::<TestnetV0, AleoTestnetV0>(&config).await?,
    };
    if let Some(path) = &config.record_store_file {
        write_record_store(
            path,
            config.network,
            &result.uuid,
            &result.records,
            RecordStoreOptions {
                secure: config.record_store_private,
                include_plaintext: false,
            },
        )?;
    }
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
            "credits_joins": join_counts.credits,
            "usdcx_joins": join_counts.usdcx,
            "arc20_eth_joins": join_counts.arc20_eth,
            "arc20_sol_joins": join_counts.arc20_sol,
            "arc20_wbtc_joins": join_counts.arc20_wbtc,
            "record_store": config.record_store_file,
            "decrypted_record_store": config.decrypted_record_store_file,
        }))?
    );
    Ok(())
}
