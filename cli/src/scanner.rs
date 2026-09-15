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
use tokio::time::{Instant, sleep, timeout};

use crate::{
    http::decode_response,
    logging::{LogLevel, event},
    records::OwnedRecord,
};

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

#[derive(Debug, Default, Eq, PartialEq)]
struct DecryptionSummary {
    decrypted: usize,
    failed: usize,
    missing_ciphertext: usize,
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
        event(
            LogLevel::Info,
            format_args!("registering view key with record scanner start_block={start}"),
        );
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
        event(
            LogLevel::Info,
            format_args!("record-scanner registration accepted start_block={start}"),
        );
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
            RegistrationState::Synced => {
                event(
                    LogLevel::Info,
                    format_args!("record-scanner registration confirmed and synchronized"),
                );
            }
            RegistrationState::Syncing => {
                event(
                    LogLevel::Info,
                    format_args!(
                        "record-scanner registration confirmed; synchronization still in progress"
                    ),
                );
                self.wait_for_sync(view_key, &uuid, start_block).await?;
            }
            RegistrationState::Missing => {
                event(
                    LogLevel::Info,
                    format_args!("record-scanner registration not active; registering"),
                );
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
        event(
            LogLevel::Info,
            format_args!(
                "waiting for record-scanner synchronization poll_interval_ms={} timeout_ms={}",
                self.sync_poll_interval.as_millis(),
                self.sync_timeout.as_millis()
            ),
        );
        let started = Instant::now();
        let mut next_progress = started;
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
                    event(
                        LogLevel::Warn,
                        format_args!(
                            "scanner registration expired during synchronization; renewing"
                        ),
                    );
                    self.renew_registration(view_key, uuid, start_block).await?;
                    re_registered = true;
                    continue;
                }
                let status: SyncStatusResponse =
                    decode_response(response, "Record-scanner sync status").await?;
                if status.synced {
                    event(
                        LogLevel::Info,
                        format_args!(
                            "record-scanner synchronization complete elapsed_seconds={}",
                            started.elapsed().as_secs()
                        ),
                    );
                    return Ok(());
                }
                if Instant::now() >= next_progress {
                    event(
                        LogLevel::Info,
                        format_args!(
                            "record-scanner synchronization in progress elapsed_seconds={}",
                            started.elapsed().as_secs()
                        ),
                    );
                    next_progress = Instant::now() + Duration::from_secs(60);
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
        event(
            LogLevel::Info,
            format_args!(
                "record scan started program={} record={}",
                program.unwrap_or("all"),
                record_name.unwrap_or("all")
            ),
        );
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
                event(
                    LogLevel::Warn,
                    format_args!("scanner registration expired during record fetch; renewing"),
                );
                self.renew_registration(view_key, uuid, start_block).await?;
                // A 422 can mean the scanner lost its in-memory key while its
                // historical scan is incomplete. Do not consume a partial
                // owned-record set; re-enter the same synchronization barrier
                // used after initial registration before retrying the fetch.
                self.wait_for_sync(view_key, uuid, start_block).await?;
                re_registered = true;
                records.clear();
                page = 0;
                continue;
            }

            let mut page_records: Vec<OwnedRecord> =
                decode_response(response, "Owned-record fetch").await?;
            let complete = page_records.len() < PAGE_SIZE;
            event(
                LogLevel::Trace,
                format_args!("owned-record page={page} records={}", page_records.len()),
            );
            records.append(&mut page_records);
            if complete {
                break;
            }
            page += 1;
        }

        let scanner_records = records.len();
        let mut records = self.remove_spent_tags(records).await?;
        let spent_filtered = scanner_records.saturating_sub(records.len());
        event(
            LogLevel::Info,
            format_args!(
                "record decryption started program={} record={} unspent_records={}",
                program.unwrap_or("all"),
                record_name.unwrap_or("all"),
                records.len()
            ),
        );
        let decryption = decrypt_records(view_key, &mut records);
        event(
            LogLevel::Info,
            format_args!(
                "record decryption complete program={} record={} decrypted={} failed={} missing_ciphertext={}",
                program.unwrap_or("all"),
                record_name.unwrap_or("all"),
                decryption.decrypted,
                decryption.failed,
                decryption.missing_ciphertext
            ),
        );
        event(
            LogLevel::Info,
            format_args!(
                "record scan complete program={} record={} scanner_records={} spent_filtered={} unspent_records={}",
                program.unwrap_or("all"),
                record_name.unwrap_or("all"),
                scanner_records,
                spent_filtered,
                records.len()
            ),
        );
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
            event(
                LogLevel::Trace,
                format_args!("checking record-tag batch size={}", batch.len()),
            );
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

fn decrypt_records<N: Network>(
    view_key: &ViewKey<N>,
    records: &mut [OwnedRecord],
) -> DecryptionSummary {
    let mut summary = DecryptionSummary::default();
    for record in records {
        let Some(ciphertext) = record.record_ciphertext.as_deref() else {
            summary.missing_ciphertext += 1;
            continue;
        };
        let Ok(ciphertext) = ciphertext.parse::<Record<N, Ciphertext<N>>>() else {
            summary.failed += 1;
            continue;
        };
        if let Ok(plaintext) = ciphertext.decrypt(view_key) {
            record.record_plaintext = Some(plaintext.to_string());
            summary.decrypted += 1;
        } else {
            summary.failed += 1;
        }
    }
    summary
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
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use snarkvm_console::{account::PrivateKey, prelude::MainnetV0};

    use super::*;

    fn respond(stream: &mut std::net::TcpStream, body: &str) {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    fn read_request_path(stream: &mut std::net::TcpStream) -> String {
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..length]);
        request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap()
            .to_owned()
    }

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

    #[tokio::test]
    async fn syncing_registration_is_polled_without_reregistering() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for body in [r#"{"synced":false}"#, r#"{"synced":true}"#] {
                let (mut stream, _) = listener.accept().unwrap();
                assert_eq!(read_request_path(&mut stream), "/status");
                respond(&mut stream, body);
            }
        });

        let private_key = PrivateKey::<MainnetV0>::new(&mut rand::rng()).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();
        let scanner =
            ScannerClient::new(endpoint, Duration::from_millis(1), Duration::from_secs(1));

        let uuid = scanner.ensure_ready(&view_key, 0).await.unwrap();
        assert_eq!(uuid, scanner_uuid(&view_key).unwrap());
        server.join().unwrap();
    }
}
