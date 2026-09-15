use crate::{
    AleoNetwork, Config, DelegatedProverClient, KeySource, RecordFamily, RecordStoreOptions,
    ScanResult, ScannerClient,
    logging::{LogLevel, event},
    read_secure_key_file, records_for_family, write_record_store,
};
use anyhow::{Context, Result};
use serde::Serialize;
use snarkvm_circuit_network::{Aleo, AleoTestnetV0, AleoV0};
use snarkvm_console::{
    account::{PrivateKey, ViewKey},
    prelude::{MainnetV0, Network, TestnetV0},
};
use std::{collections::HashSet, path::PathBuf, time::Duration};
use tokio::time::{Instant, sleep};

#[derive(Default)]
struct JoinCounts {
    credits: usize,
    usdcx: usize,
    arc20_eth: usize,
    arc20_sol: usize,
    arc20_wbtc: usize,
}

#[derive(Debug, Serialize)]
pub struct RunSummary {
    pub network: &'static str,
    pub uuid: String,
    pub record_count: usize,
    pub credits_joins: usize,
    pub usdcx_joins: usize,
    pub arc20_eth_joins: usize,
    pub arc20_sol_joins: usize,
    pub arc20_wbtc_joins: usize,
    pub record_store: Option<PathBuf>,
    pub decrypted_record_store: Option<PathBuf>,
}

async fn scan<N: Network>(
    config: &Config,
    scanner: &ScannerClient,
    view_key: &ViewKey<N>,
    uuid: &str,
) -> Result<ScanResult> {
    let families = scan_families(config);
    event(
        LogLevel::Info,
        format_args!(
            "final unspent-record scan started scope={}",
            if families.is_empty() {
                "configured-filter"
            } else {
                "enabled-families"
            }
        ),
    );
    let records = if families.is_empty() {
        scanner
            .fetch_unspent(
                view_key,
                uuid,
                config.start_block,
                config.record_program.as_deref(),
                config.record_name.as_deref(),
            )
            .await?
    } else {
        let mut records = Vec::new();
        for family in families {
            let program = family
                .record_program(config.network)
                .context("record family is not configured for this network")?;
            event(
                LogLevel::Info,
                format_args!(
                    "scanning record family={} program={} record={}",
                    family.name(),
                    program,
                    family.record_name()
                ),
            );
            records.extend(
                scanner
                    .fetch_unspent(
                        view_key,
                        uuid,
                        config.start_block,
                        Some(program),
                        Some(family.record_name()),
                    )
                    .await?,
            );
        }
        records
    };
    event(
        LogLevel::Info,
        format_args!(
            "final unspent-record scan complete records={}",
            records.len()
        ),
    );
    Ok(ScanResult {
        uuid: uuid.to_owned(),
        records,
    })
}

fn scan_families(config: &Config) -> Vec<RecordFamily> {
    let enabled = [
        (RecordFamily::Credits, config.autojoin_credits),
        (RecordFamily::Usdcx, config.autojoin_usdcx),
        (RecordFamily::Arc20Eth, config.autojoin_arc20_eth),
        (RecordFamily::Arc20Sol, config.autojoin_arc20_sol),
        (RecordFamily::Arc20Wbtc, config.autojoin_arc20_wbtc),
    ];
    let selected: Vec<_> = enabled
        .iter()
        .filter_map(|(family, enabled)| enabled.then_some(*family))
        .collect();
    if !selected.is_empty() {
        selected
    } else if config.scan_supported_records {
        enabled.iter().map(|(family, _)| *family).collect()
    } else {
        Vec::new()
    }
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
        event(
            LogLevel::Info,
            format_args!(
                "record consolidation enabled families={}",
                families.iter().filter(|(_, enabled)| *enabled).count()
            ),
        );
        let prover = DelegatedProverClient::new(config.delegated_proving_url.clone());
        for (family, enabled) in families {
            if !enabled {
                continue;
            }
            event(
                LogLevel::Info,
                format_args!(
                    "record consolidation evaluation started family={}",
                    family.name()
                ),
            );
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
            event(
                LogLevel::Info,
                format_args!(
                    "record consolidation evaluation complete family={} joins={joins}",
                    family.name()
                ),
            );
        }
    } else {
        event(
            LogLevel::Info,
            format_args!("scan-only pass; record consolidation is disabled"),
        );
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
        event(
            LogLevel::Info,
            format_args!(
                "unspent records available family={} count={}",
                family.name(),
                available.len()
            ),
        );
        if available.len() <= 1 {
            event(
                LogLevel::Info,
                format_args!(
                    "no consolidation needed family={} unspent_records={}",
                    family.name(),
                    available.len()
                ),
            );
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
        event(
            LogLevel::Info,
            format_args!(
                "submitting delegated-proving consolidation family={} join={} batch_size={} unspent_before={} expected_after={}",
                family.name(),
                joins + 1,
                count,
                available.len(),
                available.len() - count + 1
            ),
        );
        prover
            .prove_and_broadcast::<N, A>(private_key, config.network, family, selected)
            .await?;
        joins += 1;
        event(
            LogLevel::Info,
            format_args!(
                "delegated-proving consolidation broadcast accepted family={} join={joins}",
                family.name()
            ),
        );

        let deadline = Instant::now() + Duration::from_millis(config.autojoin_timeout_ms);
        event(
            LogLevel::Info,
            format_args!(
                "waiting for record scanner to observe consolidation family={} join={joins}",
                family.name()
            ),
        );
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
                event(
                    LogLevel::Info,
                    format_args!(
                        "record scanner observed consolidation family={} join={} unspent_records={}",
                        family.name(),
                        joins,
                        current_records.len()
                    ),
                );
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

pub async fn run_once(config: &Config) -> Result<RunSummary> {
    event(
        LogLevel::Info,
        format_args!(
            "pass started network={} start_block={}",
            config.network.as_str(),
            config.start_block
        ),
    );
    let (result, join_counts) = match config.network {
        AleoNetwork::Mainnet => run::<MainnetV0, AleoV0>(config).await?,
        AleoNetwork::Testnet => run::<TestnetV0, AleoTestnetV0>(config).await?,
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
        event(
            LogLevel::Info,
            format_args!(
                "ciphertext record store updated path={} records={}",
                path.display(),
                result.records.len()
            ),
        );
    } else {
        event(
            LogLevel::Info,
            format_args!("ciphertext record store disabled"),
        );
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
        event(
            LogLevel::Info,
            format_args!(
                "decrypted record store updated path={} records={}",
                path.display(),
                result.records.len()
            ),
        );
    } else {
        event(
            LogLevel::Info,
            format_args!("decrypted record store disabled"),
        );
    }
    Ok(RunSummary {
        network: config.network.as_str(),
        uuid: result.uuid,
        record_count: result.records.len(),
        credits_joins: join_counts.credits,
        usdcx_joins: join_counts.usdcx,
        arc20_eth_joins: join_counts.arc20_eth,
        arc20_sol_joins: join_counts.arc20_sol,
        arc20_wbtc_joins: join_counts.arc20_wbtc,
        record_store: config.record_store_file.clone(),
        decrypted_record_store: config.decrypted_record_store_file.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn supported_scan_selects_every_known_family() {
        let values = BTreeMap::from([
            (
                "ALEO_VIEW_KEY_FILE".to_owned(),
                "/secure/view.key".to_owned(),
            ),
            ("RECORD_STORE_FILE".to_owned(), "records.json".to_owned()),
            ("SCAN_SUPPORTED_RECORDS".to_owned(), "true".to_owned()),
        ]);
        let families = scan_families(&Config::from_values(&values).unwrap());
        assert_eq!(
            families,
            vec![
                RecordFamily::Credits,
                RecordFamily::Usdcx,
                RecordFamily::Arc20Eth,
                RecordFamily::Arc20Sol,
                RecordFamily::Arc20Wbtc,
            ]
        );
    }

    #[test]
    fn autojoin_scan_selects_only_enabled_families() {
        let values = BTreeMap::from([
            (
                "ALEO_PRIVATE_KEY_FILE".to_owned(),
                "/secure/private.key".to_owned(),
            ),
            ("RECORD_STORE_FILE".to_owned(), "records.json".to_owned()),
            ("AUTOJOIN_CREDITS".to_owned(), "true".to_owned()),
            ("AUTOJOIN_ARC20_WBTC".to_owned(), "true".to_owned()),
        ]);
        assert_eq!(
            scan_families(&Config::from_values(&values).unwrap()),
            vec![RecordFamily::Credits, RecordFamily::Arc20Wbtc]
        );
    }
}
