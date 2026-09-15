use std::{io::Read, path::Path};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

const MAX_SECRET_FILE_BYTES: u64 = 512;

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
    if metadata.len() == 0 || metadata.len() > MAX_SECRET_FILE_BYTES {
        bail!("key file must contain 1-{MAX_SECRET_FILE_BYTES} bytes");
    }

    let mut value = Zeroizing::new(String::new());
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_string(&mut value)
        .context("key file must contain UTF-8 text")?;
    if value.len() as u64 > MAX_SECRET_FILE_BYTES {
        bail!("key file changed while it was read or is too large");
    }
    if value.trim().is_empty() {
        bail!("key file is empty");
    }
    Ok(value)
}

#[cfg(not(unix))]
pub fn read_secure_key_file(_path: &Path) -> Result<Zeroizing<String>> {
    bail!("secure view-key files currently require a Unix platform")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn rejects_permissions_and_symlinks() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("autojoin-key-{}-{unique}", std::process::id()));
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
}
