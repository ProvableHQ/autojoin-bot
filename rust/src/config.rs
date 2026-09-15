use std::{env, path::PathBuf};

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
    pub fn from_env() -> Result<Self> {
        let view_key_file = optional_env("ALEO_VIEW_KEY_FILE").map(PathBuf::from);
        let private_key_file = optional_env("ALEO_PRIVATE_KEY_FILE").map(PathBuf::from);
        let key_source = match (view_key_file, private_key_file) {
            (Some(path), None) => KeySource::ViewKey(path),
            (None, Some(path)) => KeySource::PrivateKey(path),
            _ => bail!("exactly one of ALEO_VIEW_KEY_FILE or ALEO_PRIVATE_KEY_FILE is required"),
        };
        let record_store_file = optional_env("RECORD_STORE_FILE").map(PathBuf::from);
        let decrypted_record_store_file =
            optional_env("DECRYPTED_RECORD_STORE_FILE").map(PathBuf::from);
        if decrypted_record_store_file.is_some() && decrypted_record_store_file == record_store_file
        {
            bail!("DECRYPTED_RECORD_STORE_FILE must differ from RECORD_STORE_FILE");
        }

        let autojoin_credits = parse_bool_env("AUTOJOIN_CREDITS", true)?;
        let autojoin_usdcx = parse_bool_env("AUTOJOIN_USDCX", true)?;
        let autojoin_arc20_eth = parse_bool_env("AUTOJOIN_ARC20_ETH", true)?;
        let autojoin_arc20_sol = parse_bool_env("AUTOJOIN_ARC20_SOL", true)?;
        let autojoin_arc20_wbtc = parse_bool_env("AUTOJOIN_ARC20_WBTC", true)?;
        let any_arc20 = autojoin_arc20_eth || autojoin_arc20_sol || autojoin_arc20_wbtc;
        let any_autojoin = autojoin_credits || autojoin_usdcx || any_arc20;
        let network: AleoNetwork = env::var("ALEO_NETWORK")
            .unwrap_or_else(|_| "testnet".into())
            .parse()?;
        if any_autojoin && !matches!(key_source, KeySource::PrivateKey(_)) {
            bail!(
                "autojoin requires ALEO_PRIVATE_KEY_FILE; a view key can only be used when every AUTOJOIN_* setting is false"
            );
        }
        let delegated_proving_url = network.prover_endpoint();

        Ok(Self {
            autojoin_credits,
            autojoin_usdcx,
            autojoin_arc20_eth,
            autojoin_arc20_sol,
            autojoin_arc20_wbtc,
            autojoin_poll_interval_ms: positive_u64_env("AUTOJOIN_POLL_INTERVAL_MS", 5_000)?,
            autojoin_timeout_ms: positive_u64_env("AUTOJOIN_TIMEOUT_MS", 300_000)?,
            delegated_proving_url,
            key_source,
            network,
            decrypted_record_store_file,
            record_name: optional_env("RECORD_NAME"),
            record_program: optional_env("RECORD_PROGRAM"),
            record_store_file,
            record_store_private: parse_bool_env("RECORD_STORE_PRIVATE", true)?,
            scanner_root: EDGE_SCANNER_ROOT.into(),
            scan_sync_poll_interval_ms: positive_u64_env("SCAN_SYNC_POLL_INTERVAL_MS", 5_000)?,
            scan_sync_timeout_ms: positive_u64_env("SCAN_SYNC_TIMEOUT_MS", 300_000)?,
            start_block: env::var("SCAN_START_BLOCK")
                .unwrap_or_else(|_| "0".into())
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

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool> {
    match optional_env(name).as_deref() {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => bail!("{name} must be true or false"),
    }
}

fn positive_u64_env(name: &str, default: u64) -> Result<u64> {
    match optional_env(name) {
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
