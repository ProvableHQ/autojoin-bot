use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::{PublicKey, aead::OsRng};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use snarkvm_console::{
    account::{Field, ViewKey},
    prelude::{Network, One, ToBytes, ToField},
    program::{Ciphertext, Record},
};
use tokio::time::{sleep, timeout};

use crate::{http::decode_response, records::OwnedRecord};

const PAGE_SIZE: usize = 1000;
const TAG_BATCH_SIZE: usize = 1000;
const SCANNER_DOMAIN: &str = "RecordScannerV0";

#[derive(Clone)]
pub struct ScannerClient {
    client: Client,
    endpoint: String,
    sync_poll_interval: Duration,
    sync_timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct PubkeyResponse {
    key_id: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct RegistrationResponse {
    uuid: String,
}

#[derive(Deserialize)]
struct SyncStatusResponse {
    synced: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum RegistrationState {
    Missing,
    Syncing,
    Synced,
}

#[derive(Debug, Serialize)]
struct EncryptedRegistrationRequest {
    key_id: String,
    ciphertext: String,
}

impl ScannerClient {
    pub fn new(endpoint: String, sync_poll_interval: Duration, sync_timeout: Duration) -> Self {
        Self {
            client: Client::new(),
            endpoint,
            sync_poll_interval,
            sync_timeout,
        }
    }

    pub async fn register<N: Network>(&self, view_key: &ViewKey<N>, start: u32) -> Result<String> {
        let pubkey = self
            .client
            .get(format!("{}/pubkey", self.endpoint))
            .send()
            .await
            .context("failed to request scanner public key")?;
        let pubkey: PubkeyResponse = decode_response(pubkey, "Scanner public-key request").await?;

        let public_key: [u8; 32] = STANDARD
            .decode(pubkey.public_key)
            .context("scanner returned an invalid base64 public key")?
            .try_into()
            .map_err(|_| anyhow!("scanner public key must be 32 bytes"))?;

        let mut plaintext = view_key.to_bytes_le()?;
        plaintext.extend_from_slice(&start.to_le_bytes());
        let ciphertext = PublicKey::from(public_key)
            .seal(&mut OsRng, &plaintext)
            .map_err(|error| anyhow!("failed to encrypt scanner registration: {error}"))?;

        let response = self
            .client
            .post(format!("{}/register/encrypted", self.endpoint))
            .json(&EncryptedRegistrationRequest {
                key_id: pubkey.key_id,
                ciphertext: STANDARD.encode(ciphertext),
            })
            .send()
            .await
            .context("failed to register with scanner")?;
        let registration: RegistrationResponse =
            decode_response(response, "Scanner registration").await?;
        Ok(registration.uuid)
    }

    /// Reuse an active scanner registration whenever possible. The UUID is
    /// deterministic, so status can be checked without sending the view key
    /// again. Only a missing registration is created or renewed.
    pub async fn ensure_ready<N: Network>(
        &self,
        view_key: &ViewKey<N>,
        start_block: u32,
    ) -> Result<String> {
        let uuid = scanner_uuid(view_key)?;
        match self.registration_state(&uuid).await? {
            RegistrationState::Synced => {}
            RegistrationState::Syncing => {
                self.wait_for_sync(view_key, &uuid, start_block).await?;
            }
            RegistrationState::Missing => {
                self.renew_registration(view_key, &uuid, start_block)
                    .await?;
                self.wait_for_sync(view_key, &uuid, start_block).await?;
            }
        }
        Ok(uuid)
    }

    async fn registration_state(&self, uuid: &str) -> Result<RegistrationState> {
        let response = self
            .client
            .post(format!("{}/status", self.endpoint))
            .json(uuid)
            .send()
            .await
            .context("failed to check scanner registration status")?;
        if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
            return Ok(RegistrationState::Missing);
        }
        let status: SyncStatusResponse =
            decode_response(response, "Record-scanner registration status").await?;
        Ok(if status.synced {
            RegistrationState::Synced
        } else {
            RegistrationState::Syncing
        })
    }

    async fn renew_registration<N: Network>(
        &self,
        view_key: &ViewKey<N>,
        uuid: &str,
        start_block: u32,
    ) -> Result<()> {
        let renewed_uuid = self.register(view_key, start_block).await?;
        if renewed_uuid != uuid {
            anyhow::bail!("record scanner returned a different UUID after re-registration");
        }
        Ok(())
    }

    /// Wait for the historical scan before treating a small record set as complete.
    pub async fn wait_for_sync<N: Network>(
        &self,
        view_key: &ViewKey<N>,
        uuid: &str,
        start_block: u32,
    ) -> Result<()> {
        timeout(self.sync_timeout, async {
            let mut re_registered = false;
            loop {
                let response = self
                    .client
                    .post(format!("{}/status", self.endpoint))
                    .json(uuid)
                    .send()
                    .await
                    .context("failed to check scanner sync status")?;
                if response.status() == StatusCode::UNPROCESSABLE_ENTITY && !re_registered {
                    // RSS derives the UUID from the view key, so re-registration preserves it.
                    self.renew_registration(view_key, uuid, start_block).await?;
                    re_registered = true;
                    continue;
                }
                let status: SyncStatusResponse =
                    decode_response(response, "Record-scanner sync status").await?;
                if status.synced {
                    return Ok(());
                }
                sleep(self.sync_poll_interval).await;
            }
        })
        .await
        .context(
            "timed out waiting for initial scanner synchronization; increase SCAN_SYNC_TIMEOUT_MS",
        )?
    }

    pub async fn fetch_unspent<N: Network>(
        &self,
        view_key: &ViewKey<N>,
        uuid: &str,
        start_block: u32,
        program: Option<&str>,
        record_name: Option<&str>,
    ) -> Result<Vec<OwnedRecord>> {
        let mut records = Vec::new();
        let mut page = 0;
        let mut re_registered = false;

        loop {
            let body = owned_body(uuid, program, record_name, page);
            let response = self
                .client
                .post(format!("{}/records/owned", self.endpoint))
                .json(&body)
                .send()
                .await
                .context("failed to fetch owned records")?;

            // A process restart can forget the in-memory scanner key.
            if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
                if re_registered {
                    return decode_response(response, "Owned-record fetch after re-registration")
                        .await;
                }
                self.renew_registration(view_key, uuid, start_block).await?;
                self.wait_for_sync(view_key, uuid, start_block).await?;
                re_registered = true;
                records.clear();
                page = 0;
                continue;
            }

            let mut page_records: Vec<OwnedRecord> =
                decode_response(response, "Owned-record fetch").await?;
            let complete = page_records.len() < PAGE_SIZE;
            records.append(&mut page_records);
            if complete {
                break;
            }
            page += 1;
        }

        let mut records = self.remove_spent_tags(records).await?;
        decrypt_records(view_key, &mut records);
        Ok(records)
    }

    async fn remove_spent_tags(&self, records: Vec<OwnedRecord>) -> Result<Vec<OwnedRecord>> {
        let mut tags: Vec<String> = records
            .iter()
            .filter_map(|record| record.tag.clone())
            .collect();
        tags.sort_unstable();
        tags.dedup();

        let mut spent = HashMap::new();
        for batch in tags.chunks(TAG_BATCH_SIZE) {
            let response = self
                .client
                .post(format!("{}/records/tags", self.endpoint))
                .json(batch)
                .send()
                .await
                .context("failed to check record tags")?;
            let statuses: HashMap<String, bool> =
                decode_response(response, "Record-tag check").await?;
            spent.extend(statuses);
        }

        Ok(records
            .into_iter()
            .filter(|record| {
                record
                    .tag
                    .as_ref()
                    .is_none_or(|tag| spent.get(tag) != Some(&true))
            })
            .collect())
    }
}

fn scanner_uuid<N: Network>(view_key: &ViewKey<N>) -> Result<String> {
    let domain = Field::<N>::new_domain_separator(SCANNER_DOMAIN);
    Ok(N::hash_psd4(&[domain, view_key.to_field()?, Field::<N>::one()])?.to_string())
}

fn decrypt_records<N: Network>(view_key: &ViewKey<N>, records: &mut [OwnedRecord]) {
    for record in records {
        let Some(ciphertext) = record.record_ciphertext.as_deref() else {
            continue;
        };
        let Ok(ciphertext) = ciphertext.parse::<Record<N, Ciphertext<N>>>() else {
            continue;
        };
        if let Ok(plaintext) = ciphertext.decrypt(view_key) {
            record.record_plaintext = Some(plaintext.to_string());
        }
    }
}

fn owned_body(uuid: &str, program: Option<&str>, record_name: Option<&str>, page: usize) -> Value {
    let mut filter = Map::new();
    filter.insert("results_per_page".into(), PAGE_SIZE.into());
    filter.insert("page".into(), page.into());
    if let Some(program) = program {
        filter.insert("programs".into(), json!([program]));
    }
    if let Some(record_name) = record_name {
        filter.insert("records".into(), json!([record_name]));
    }
    json!({ "uuid": uuid, "unspent": true, "filter": filter })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_request_uses_wire_names_and_pagination() {
        assert_eq!(
            owned_body("1field", Some("credits.aleo"), Some("credits"), 2),
            json!({
                "uuid": "1field",
                "unspent": true,
                "filter": {
                    "programs": ["credits.aleo"],
                    "records": ["credits"],
                    "results_per_page": 1000,
                    "page": 2
                }
            })
        );
    }
}
