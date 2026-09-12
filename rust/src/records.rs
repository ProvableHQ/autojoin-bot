use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

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

pub fn credits_records(records: &[OwnedRecord]) -> Result<Vec<&OwnedRecord>> {
    let records: Vec<_> = records
        .iter()
        .filter(|record| {
            record.program_name.as_deref() == Some("credits.aleo")
                && record.record_name.as_deref() == Some("credits")
        })
        .collect();
    if records
        .iter()
        .any(|record| record.record_plaintext.is_none() || record.tag.is_none())
    {
        bail!("owned credits record is missing plaintext or tag");
    }
    Ok(records)
}
