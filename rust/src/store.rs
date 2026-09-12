use std::{
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{network::AleoNetwork, records::OwnedRecord};

#[cfg(unix)]
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const STORE_VERSION: u32 = 1;

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
            record_plaintext: include_plaintext
                .then(|| record.record_plaintext.clone())
                .flatten(),
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn owner_only_store_omits_plaintext() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("autojoin-store-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("records.json");
        let records = vec![sample_record()];
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
        assert_eq!(
            read_record_store(&decrypted_path, true).unwrap().records[0]
                .record_plaintext
                .as_deref(),
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

    fn sample_record() -> OwnedRecord {
        OwnedRecord {
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
        }
    }
}
