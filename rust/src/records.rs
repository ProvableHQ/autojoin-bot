use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::network::AleoNetwork;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordFamily {
    Credits,
    Usdcx,
}

impl RecordFamily {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Credits => "credits",
            Self::Usdcx => "usdcx",
        }
    }

    pub const fn record_program(self, network: AleoNetwork) -> &'static str {
        match (self, network) {
            (Self::Credits, _) => "credits.aleo",
            (Self::Usdcx, AleoNetwork::Mainnet) => "usdcx_stablecoin.aleo",
            (Self::Usdcx, AleoNetwork::Testnet) => "test_usdcx_stablecoin.aleo",
        }
    }

    pub const fn record_name(self) -> &'static str {
        match self {
            Self::Credits => "credits",
            Self::Usdcx => "Token",
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
            record.program_name.as_deref() == Some(family.record_program(network))
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
            "usdcx_stablecoin.aleo"
        );
        assert_eq!(
            RecordFamily::Usdcx.record_program(AleoNetwork::Testnet),
            "test_usdcx_stablecoin.aleo"
        );
    }
}
