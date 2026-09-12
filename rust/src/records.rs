use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::network::AleoNetwork;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordFamily {
    Credits,
    Usdcx,
    Arc20Eth,
    Arc20Sol,
    Arc20Wbtc,
}

impl RecordFamily {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Credits => "credits",
            Self::Usdcx => "usdcx",
            Self::Arc20Eth => "arc20-eth",
            Self::Arc20Sol => "arc20-sol",
            Self::Arc20Wbtc => "arc20-wbtc",
        }
    }

    pub const fn record_program(self, network: AleoNetwork) -> Option<&'static str> {
        match (self, network) {
            (Self::Credits, _) => Some("credits.aleo"),
            (Self::Usdcx, AleoNetwork::Mainnet) => Some("usdcx_stablecoin.aleo"),
            (Self::Usdcx, AleoNetwork::Testnet) => Some("test_usdcx_stablecoin.aleo"),
            (Self::Arc20Eth, AleoNetwork::Mainnet) => Some("arc20_eth.aleo"),
            (Self::Arc20Sol, AleoNetwork::Mainnet) => Some("arc20_sol.aleo"),
            (Self::Arc20Wbtc, AleoNetwork::Mainnet) => Some("arc20_wbtc.aleo"),
            (Self::Arc20Eth, AleoNetwork::Testnet) => Some("test_arc20_eth.aleo"),
            (Self::Arc20Sol, AleoNetwork::Testnet) => Some("test_arc20_sol.aleo"),
            (Self::Arc20Wbtc, AleoNetwork::Testnet) => Some("test_arc20_wbtc.aleo"),
        }
    }

    pub const fn record_name(self) -> &'static str {
        match self {
            Self::Credits => "credits",
            Self::Usdcx | Self::Arc20Eth | Self::Arc20Sol | Self::Arc20Wbtc => "Token",
        }
    }

    pub const fn token_identifier(self, network: AleoNetwork) -> Option<&'static str> {
        match (self, network) {
            (Self::Arc20Eth, AleoNetwork::Mainnet) => Some("arc20_eth"),
            (Self::Arc20Sol, AleoNetwork::Mainnet) => Some("arc20_sol"),
            (Self::Arc20Wbtc, AleoNetwork::Mainnet) => Some("arc20_wbtc"),
            (Self::Arc20Eth, AleoNetwork::Testnet) => Some("test_arc20_eth"),
            (Self::Arc20Sol, AleoNetwork::Testnet) => Some("test_arc20_sol"),
            (Self::Arc20Wbtc, AleoNetwork::Testnet) => Some("test_arc20_wbtc"),
            (Self::Credits | Self::Usdcx, _) => None,
        }
    }

    pub const fn max_batch(self) -> usize {
        match self {
            Self::Arc20Eth | Self::Arc20Sol | Self::Arc20Wbtc => 15,
            Self::Credits | Self::Usdcx => 16,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct OwnedRecord {
    pub block_height: Option<i32>,
    pub block_timestamp: Option<i64>,
    pub commitment: Option<String>,
    pub function_name: Option<String>,
    pub output_index: Option<i16>,
    pub owner: Option<String>,
    pub program_name: Option<String>,
    pub record_ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_plaintext: Option<String>,
    pub record_name: Option<String>,
    pub sender: Option<String>,
    pub spent: Option<bool>,
    pub tag: Option<String>,
    pub transaction_id: Option<String>,
    pub transition_id: Option<String>,
    pub transaction_index: Option<i16>,
    pub transition_index: Option<i16>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub uuid: String,
    pub records: Vec<OwnedRecord>,
}

pub fn records_for_family(
    records: &[OwnedRecord],
    family: RecordFamily,
    network: AleoNetwork,
) -> Result<Vec<&OwnedRecord>> {
    let records: Vec<_> = records
        .iter()
        .filter(|record| {
            record.program_name.as_deref() == family.record_program(network)
                && record.record_name.as_deref() == Some(family.record_name())
        })
        .collect();
    if records
        .iter()
        .any(|record| record.record_plaintext.is_none() || record.tag.is_none())
    {
        bail!("owned {} record is missing plaintext or tag", family.name());
    }
    Ok(records)
}

pub fn credits_records(records: &[OwnedRecord]) -> Result<Vec<&OwnedRecord>> {
    records_for_family(records, RecordFamily::Credits, AleoNetwork::Mainnet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usdcx_record_program_is_network_specific() {
        assert_eq!(
            RecordFamily::Usdcx.record_program(AleoNetwork::Mainnet),
            Some("usdcx_stablecoin.aleo")
        );
        assert_eq!(
            RecordFamily::Usdcx.record_program(AleoNetwork::Testnet),
            Some("test_usdcx_stablecoin.aleo")
        );
    }

    #[test]
    fn arc20_metadata_is_network_specific() {
        assert_eq!(
            RecordFamily::Arc20Eth.record_program(AleoNetwork::Mainnet),
            Some("arc20_eth.aleo")
        );
        assert_eq!(
            RecordFamily::Arc20Eth.record_program(AleoNetwork::Testnet),
            Some("test_arc20_eth.aleo")
        );
        assert_eq!(
            RecordFamily::Arc20Eth.token_identifier(AleoNetwork::Mainnet),
            Some("arc20_eth")
        );
        assert_eq!(
            RecordFamily::Arc20Eth.token_identifier(AleoNetwork::Testnet),
            Some("test_arc20_eth")
        );
        assert_eq!(RecordFamily::Arc20Eth.max_batch(), 15);
    }
}
