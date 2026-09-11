use std::{
    collections::HashMap,
    env,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::{PublicKey, aead::OsRng};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use snarkvm_console::{
    account::ViewKey,
    prelude::{Network, ToBytes},
    program::{Ciphertext, Record},
};
use zeroize::Zeroizing;

pub const EDGE_SCANNER_ROOT: &str = "https://edge.provable.com/api/scanner";
const PAGE_SIZE: usize = 1000;
const TAG_BATCH_SIZE: usize = 1000;
const MAX_VIEW_KEY_FILE_BYTES: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AleoNetwork {
    Mainnet,
    Testnet,
}

impl AleoNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

impl FromStr for AleoNetwork {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => bail!("ALEO_NETWORK must be either mainnet or testnet"),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub key_source: KeySource,
    pub network: AleoNetwork,
    pub record_name: Option<String>,
    pub record_program: Option<String>,
    pub scanner_root: String,
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

        Ok(Self {
            key_source,
            network: env::var("ALEO_NETWORK")
                .unwrap_or_else(|_| "testnet".into())
                .parse()?,
            record_name: optional_env("RECORD_NAME"),
            record_program: optional_env("RECORD_PROGRAM"),
            scanner_root: EDGE_SCANNER_ROOT.into(),
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

#[cfg(unix)]
pub fn read_secure_key_file(path: &Path) -> Result<Zeroizing<String>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("failed to securely open key file at {}", path.display()))?;
    let metadata = file.metadata()?;

    if !metadata.is_file() {
        bail!("key file must be a regular file");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("key file must not grant group or other access (use chmod 600)");
    }
    // SAFETY: geteuid takes no pointers and has no preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("key file must be owned by the current user");
    }
    if metadata.len() == 0 || metadata.len() > MAX_VIEW_KEY_FILE_BYTES {
        bail!("key file must contain 1-{MAX_VIEW_KEY_FILE_BYTES} bytes");
    }

    let mut value = Zeroizing::new(String::new());
    file.take(MAX_VIEW_KEY_FILE_BYTES + 1)
        .read_to_string(&mut value)
        .context("key file must contain UTF-8 text")?;
    if value.len() as u64 > MAX_VIEW_KEY_FILE_BYTES {
        bail!("key file changed while it was read or is too large");
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("key file is empty");
    }
    Ok(value)
}

#[cfg(not(unix))]
pub fn read_secure_key_file(_path: &Path) -> Result<Zeroizing<String>> {
    bail!("secure view-key files currently require a Unix platform")
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

#[derive(Clone)]
pub struct ScannerClient {
    client: Client,
    endpoint: String,
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

#[derive(Debug, Serialize)]
struct EncryptedRegistrationRequest {
    key_id: String,
    ciphertext: String,
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

impl ScannerClient {
    pub fn new(endpoint: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
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

        loop {
            let body = owned_body(uuid, program, record_name, page);
            let mut response = self
                .client
                .post(format!("{}/records/owned", self.endpoint))
                .json(&body)
                .send()
                .await
                .context("failed to fetch owned records")?;

            // The API-parity contract returns 422 when a process restart has
            // forgotten the in-memory key. Re-register once and retry the page.
            if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
                self.register(view_key, start_block).await?;
                response = self
                    .client
                    .post(format!("{}/records/owned", self.endpoint))
                    .json(&body)
                    .send()
                    .await
                    .context("failed to retry owned-record fetch")?;
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

async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    action: &str,
) -> Result<T> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("{action} failed (HTTP {status}): {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("{action} returned invalid JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn secure_key_file_rejects_permissions_and_symlinks() {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{OpenOptionsExt, symlink},
            time::{SystemTime, UNIX_EPOCH},
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            env::temp_dir().join(format!("autojoin-key-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let key_path = directory.join("account.key");
        let mut key_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .unwrap();
        writeln!(key_file, "AViewKey1example").unwrap();
        drop(key_file);

        assert_eq!(
            &*read_secure_key_file(&key_path).unwrap(),
            "AViewKey1example\n"
        );
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            read_secure_key_file(&key_path)
                .unwrap_err()
                .to_string()
                .contains("chmod 600")
        );
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let link_path = directory.join("link.key");
        symlink(&key_path, &link_path).unwrap();
        assert!(read_secure_key_file(&link_path).is_err());
        fs::remove_dir_all(directory).unwrap();
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

    #[test]
    fn network_parsing_is_strict() {
        assert_eq!(
            "mainnet".parse::<AleoNetwork>().unwrap(),
            AleoNetwork::Mainnet
        );
        assert_eq!(
            "TESTNET".parse::<AleoNetwork>().unwrap(),
            AleoNetwork::Testnet
        );
        assert!("devnet".parse::<AleoNetwork>().is_err());
    }
}
