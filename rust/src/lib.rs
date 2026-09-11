use std::{
    collections::HashMap,
    env,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::{
    fs::{self, File, OpenOptions},
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
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const STORE_VERSION: u32 = 1;

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
    pub decrypted_record_store_file: Option<PathBuf>,
    pub record_name: Option<String>,
    pub record_program: Option<String>,
    pub record_store_file: PathBuf,
    pub record_store_private: bool,
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
        let record_store_file = optional_env("RECORD_STORE_FILE")
            .map(PathBuf::from)
            .context("RECORD_STORE_FILE is required")?;
        let decrypted_record_store_file =
            optional_env("DECRYPTED_RECORD_STORE_FILE").map(PathBuf::from);
        if decrypted_record_store_file.as_ref() == Some(&record_store_file) {
            bail!("DECRYPTED_RECORD_STORE_FILE must differ from RECORD_STORE_FILE");
        }

        Ok(Self {
            key_source,
            network: env::var("ALEO_NETWORK")
                .unwrap_or_else(|_| "testnet".into())
                .parse()?,
            decrypted_record_store_file,
            record_name: optional_env("RECORD_NAME"),
            record_program: optional_env("RECORD_PROGRAM"),
            record_store_file,
            record_store_private: parse_bool_env("RECORD_STORE_PRIVATE", true)?,
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

#[cfg(unix)]
fn validate_store_path(path: &Path, secure: bool) -> Result<&Path> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect record-store parent {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("record-store parent must be a real directory, not a symlink");
    }
    // SAFETY: geteuid takes no pointers and has no preconditions.
    if secure && parent_metadata.uid() != unsafe { libc::geteuid() } {
        bail!("record-store parent must be owned by the current user");
    }
    if secure && parent_metadata.permissions().mode() & 0o022 != 0 {
        bail!("record-store parent must not be writable by group or others");
    }

    if path.exists() || fs::symlink_metadata(path).is_ok() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("record store must be a regular file, not a symlink");
        }
        if secure && metadata.uid() != unsafe { libc::geteuid() } {
            bail!("record store must be owned by the current user");
        }
        if secure && metadata.permissions().mode() & 0o077 != 0 {
            bail!("record store must not grant group or other access (use chmod 600)");
        }
    }
    Ok(parent)
}

#[cfg(unix)]
pub fn write_record_store(
    path: &Path,
    network: AleoNetwork,
    uuid: &str,
    records: &[OwnedRecord],
    options: RecordStoreOptions,
) -> Result<()> {
    let updated_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    write_record_store_at(path, network, uuid, records, updated_at, options)
}

#[cfg(unix)]
fn write_record_store_at(
    path: &Path,
    network: AleoNetwork,
    uuid: &str,
    records: &[OwnedRecord],
    updated_at: u64,
    options: RecordStoreOptions,
) -> Result<()> {
    let parent = validate_store_path(path, options.secure)?;
    if fs::symlink_metadata(path).is_ok() {
        let current = read_record_store(path, options.secure)?;
        if current.network != network.as_str()
            || current.uuid != uuid
            || current.contains_plaintext != options.include_plaintext
        {
            bail!("record store belongs to a different network, UUID, or record format");
        }
    }
    let snapshot = RecordStore {
        version: STORE_VERSION,
        network: network.as_str().into(),
        uuid: uuid.into(),
        contains_plaintext: options.include_plaintext,
        updated_at,
        records: records
            .iter()
            .map(|record| StoredRecord::new(record, options.include_plaintext))
            .collect(),
    };
    let mut encoded = serde_json::to_vec_pretty(&snapshot)?;
    encoded.push(b'\n');

    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let filename = path
        .file_name()
        .context("RECORD_STORE_FILE must name a file")?;
    let temporary = parent.join(format!(
        ".{}.{}.{suffix}.tmp",
        filename.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if options.secure { 0o600 } else { 0o644 })
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
pub fn read_record_store(path: &Path, secure: bool) -> Result<RecordStore> {
    validate_store_path(path, secure)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_STORE_BYTES {
        bail!("record store exceeds 64 MiB");
    }
    let store: RecordStore = serde_json::from_reader(file)?;
    if store.version != STORE_VERSION {
        bail!("unsupported record-store version {}", store.version);
    }
    Ok(store)
}

#[cfg(not(unix))]
pub fn write_record_store(
    _path: &Path,
    _network: AleoNetwork,
    _uuid: &str,
    _records: &[OwnedRecord],
    _options: RecordStoreOptions,
) -> Result<()> {
    bail!("secure record storage currently requires a Unix platform")
}

#[cfg(not(unix))]
pub fn read_record_store(_path: &Path, _secure: bool) -> Result<RecordStore> {
    bail!("secure record storage currently requires a Unix platform")
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

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct RecordStore {
    pub version: u32,
    pub network: String,
    pub uuid: String,
    pub contains_plaintext: bool,
    pub updated_at: u64,
    pub records: Vec<StoredRecord>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct StoredRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_plaintext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_name: Option<String>,
    pub spent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_index: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_index: Option<i16>,
}

impl StoredRecord {
    fn new(record: &OwnedRecord, include_plaintext: bool) -> Self {
        Self {
            block_height: record.block_height,
            commitment: record.commitment.clone(),
            function_name: record.function_name.clone(),
            output_index: record.output_index,
            program_name: record.program_name.clone(),
            record_ciphertext: record.record_ciphertext.clone(),
            record_plaintext: if include_plaintext {
                record.record_plaintext.clone()
            } else {
                None
            },
            record_name: record.record_name.clone(),
            spent: false,
            tag: record.tag.clone(),
            transaction_id: record.transaction_id.clone(),
            transition_id: record.transition_id.clone(),
            transaction_index: record.transaction_index,
            transition_index: record.transition_index,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RecordStoreOptions {
    pub secure: bool,
    pub include_plaintext: bool,
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

    #[cfg(unix)]
    #[test]
    fn record_store_is_owner_only_and_omits_plaintext() {
        use std::{
            fs,
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            env::temp_dir().join(format!("autojoin-store-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("records.json");
        let records = vec![OwnedRecord {
            block_height: Some(42),
            block_timestamp: None,
            commitment: Some("commitment".into()),
            function_name: None,
            output_index: None,
            owner: Some("owner is omitted".into()),
            program_name: Some("credits.aleo".into()),
            record_ciphertext: Some("record1ciphertext".into()),
            record_plaintext: Some("secret plaintext".into()),
            record_name: Some("credits".into()),
            sender: Some("sender is omitted".into()),
            spent: Some(false),
            tag: Some("2field".into()),
            transaction_id: None,
            transition_id: None,
            transaction_index: None,
            transition_index: None,
        }];

        let ciphertext_options = RecordStoreOptions {
            secure: true,
            include_plaintext: false,
        };
        write_record_store_at(
            &path,
            AleoNetwork::Testnet,
            "1field",
            &records,
            2,
            ciphertext_options,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret plaintext"));
        assert!(!raw.contains("owner is omitted"));
        assert!(!raw.contains("sender is omitted"));

        let store = read_record_store(&path, true).unwrap();
        assert!(!store.contains_plaintext);
        assert_eq!(store.updated_at, 2);
        assert_eq!(store.records.len(), 1);
        assert_eq!(
            store.records[0].record_ciphertext.as_deref(),
            Some("record1ciphertext")
        );
        assert!(
            write_record_store_at(
                &path,
                AleoNetwork::Mainnet,
                "different",
                &[],
                3,
                ciphertext_options,
            )
            .unwrap_err()
            .to_string()
            .contains("different network, UUID, or record format")
        );

        let decrypted_path = directory.join("decrypted.json");
        write_record_store_at(
            &decrypted_path,
            AleoNetwork::Testnet,
            "1field",
            &records,
            2,
            RecordStoreOptions {
                secure: true,
                include_plaintext: true,
            },
        )
        .unwrap();
        let decrypted = read_record_store(&decrypted_path, true).unwrap();
        assert!(decrypted.contains_plaintext);
        assert_eq!(
            decrypted.records[0].record_plaintext.as_deref(),
            Some("secret plaintext")
        );

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        let public_path = directory.join("public-records.json");
        write_record_store_at(
            &public_path,
            AleoNetwork::Testnet,
            "1field",
            &records,
            2,
            RecordStoreOptions {
                secure: false,
                include_plaintext: false,
            },
        )
        .unwrap();
        assert_eq!(
            read_record_store(&public_path, false)
                .unwrap()
                .records
                .len(),
            1
        );
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
