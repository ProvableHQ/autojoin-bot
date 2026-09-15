use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result, bail};

use crate::network::{AleoNetwork, EDGE_SCANNER_ROOT};

#[derive(Debug)]
pub struct Config {
    pub autojoin_credits: bool,
    pub autojoin_usdcx: bool,
    pub autojoin_arc20_eth: bool,
    pub autojoin_arc20_sol: bool,
    pub autojoin_arc20_wbtc: bool,
    pub autojoin_poll_interval_ms: u64,
    pub autojoin_timeout_ms: u64,
    pub delegated_proving_url: String,
    pub key_source: KeySource,
    pub network: AleoNetwork,
    pub decrypted_record_store_file: Option<PathBuf>,
    pub record_name: Option<String>,
    pub record_program: Option<String>,
    pub record_store_file: Option<PathBuf>,
    pub record_store_private: bool,
    pub scanner_root: String,
    pub scan_supported_records: bool,
    pub scan_sync_poll_interval_ms: u64,
    pub scan_sync_timeout_ms: u64,
    pub start_block: u32,
}

#[derive(Debug)]
pub enum KeySource {
    ViewKey(PathBuf),
    PrivateKey(PathBuf),
}

impl Config {
    pub fn from_values(values: &BTreeMap<String, String>) -> Result<Self> {
        let optional = |name| {
            values
                .get(name)
                .cloned()
                .filter(|value| !value.trim().is_empty())
        };
        let view_key_file = optional("ALEO_VIEW_KEY_FILE").map(PathBuf::from);
        let private_key_file = optional("ALEO_PRIVATE_KEY_FILE").map(PathBuf::from);
        let key_source = match (view_key_file, private_key_file) {
            (Some(path), None) => KeySource::ViewKey(path),
            (None, Some(path)) => KeySource::PrivateKey(path),
            _ => bail!("exactly one of ALEO_VIEW_KEY_FILE or ALEO_PRIVATE_KEY_FILE is required"),
        };
        let record_store_file = optional("RECORD_STORE_FILE").map(PathBuf::from);
        let decrypted_record_store_file =
            optional("DECRYPTED_RECORD_STORE_FILE").map(PathBuf::from);
        if decrypted_record_store_file.is_some() && decrypted_record_store_file == record_store_file
        {
            bail!("DECRYPTED_RECORD_STORE_FILE must differ from RECORD_STORE_FILE");
        }

        let parse_bool = |name, default| parse_bool_value(name, optional(name), default);
        let positive_u64 = |name, default| positive_u64_value(name, optional(name), default);
        let autojoin_credits = parse_bool("AUTOJOIN_CREDITS", false)?;
        let autojoin_usdcx = parse_bool("AUTOJOIN_USDCX", false)?;
        let autojoin_arc20_eth = parse_bool("AUTOJOIN_ARC20_ETH", false)?;
        let autojoin_arc20_sol = parse_bool("AUTOJOIN_ARC20_SOL", false)?;
        let autojoin_arc20_wbtc = parse_bool("AUTOJOIN_ARC20_WBTC", false)?;
        let any_arc20 = autojoin_arc20_eth || autojoin_arc20_sol || autojoin_arc20_wbtc;
        let any_autojoin = autojoin_credits || autojoin_usdcx || any_arc20;
        let network: AleoNetwork = optional("ALEO_NETWORK")
            .unwrap_or_else(|| "mainnet".into())
            .parse()?;
        if any_autojoin && !matches!(key_source, KeySource::PrivateKey(_)) {
            bail!("autojoin requires ALEO_PRIVATE_KEY_FILE to sign authorizations");
        }
        let delegated_proving_url = network.prover_endpoint();
        let scan_supported_records = parse_bool("SCAN_SUPPORTED_RECORDS", false)?;
        if scan_supported_records && any_autojoin {
            bail!("SCAN_SUPPORTED_RECORDS is for scan-only mode");
        }
        if scan_supported_records
            && (optional("RECORD_PROGRAM").is_some() || optional("RECORD_NAME").is_some())
        {
            bail!("SCAN_SUPPORTED_RECORDS cannot be combined with custom record filters");
        }

        Ok(Self {
            autojoin_credits,
            autojoin_usdcx,
            autojoin_arc20_eth,
            autojoin_arc20_sol,
            autojoin_arc20_wbtc,
            autojoin_poll_interval_ms: positive_u64("AUTOJOIN_POLL_INTERVAL_MS", 5_000)?,
            autojoin_timeout_ms: positive_u64("AUTOJOIN_TIMEOUT_MS", 300_000)?,
            delegated_proving_url,
            key_source,
            network,
            decrypted_record_store_file,
            record_name: optional("RECORD_NAME"),
            record_program: optional("RECORD_PROGRAM"),
            record_store_file,
            record_store_private: parse_bool("RECORD_STORE_PRIVATE", true)?,
            scanner_root: EDGE_SCANNER_ROOT.into(),
            scan_supported_records,
            scan_sync_poll_interval_ms: positive_u64("SCAN_SYNC_POLL_INTERVAL_MS", 5_000)?,
            scan_sync_timeout_ms: positive_u64("SCAN_SYNC_TIMEOUT_MS", 300_000)?,
            start_block: optional("SCAN_START_BLOCK")
                .unwrap_or_else(|| "0".into())
                .parse()
                .context("SCAN_START_BLOCK must be an integer between 0 and 4294967295")?,
        })
    }

    pub fn endpoint(&self) -> String {
        format!(
            "{}/{}",
            self.scanner_root.trim_end_matches('/'),
            self.network.as_str()
        )
    }
}

fn parse_bool_value(name: &str, value: Option<String>, default: bool) -> Result<bool> {
    match value.as_deref() {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => bail!("{name} must be true or false"),
    }
}

fn positive_u64_value(name: &str, value: Option<String>, default: u64) -> Result<u64> {
    match value {
        None => Ok(default),
        Some(value) => {
            let parsed = value
                .parse::<u64>()
                .with_context(|| format!("{name} must be a positive integer"))?;
            if parsed == 0 {
                bail!("{name} must be a positive integer");
            }
            Ok(parsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_is_the_default_network() {
        let values = BTreeMap::from([
            (
                "ALEO_VIEW_KEY_FILE".to_owned(),
                "/secure/view.key".to_owned(),
            ),
            ("RECORD_STORE_FILE".to_owned(), "records.json".to_owned()),
        ]);
        assert_eq!(
            Config::from_values(&values).unwrap().network,
            AleoNetwork::Mainnet
        );
        assert_eq!(
            Config::from_values(&values).unwrap().delegated_proving_url,
            "https://edge.provable.com/api/prove/mainnet"
        );
        assert!(Config::from_values(&values).unwrap().record_store_private);
        assert!(
            Config::from_values(&values)
                .unwrap()
                .record_store_file
                .is_some()
        );
    }

    #[test]
    fn record_snapshots_are_optional_by_default() {
        let values = BTreeMap::from([(
            "ALEO_VIEW_KEY_FILE".to_owned(),
            "/secure/view.key".to_owned(),
        )]);
        let config = Config::from_values(&values).unwrap();

        assert!(config.record_store_file.is_none());
        assert!(config.decrypted_record_store_file.is_none());
    }
}
