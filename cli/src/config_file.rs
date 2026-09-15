use crate::ui;
use crate::{Config, LogLevel};
use anyhow::{Context, Result, bail};
use snarkvm_console::{
    account::{PrivateKey, ViewKey},
    prelude::{MainnetV0, TestnetV0},
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const CONFIG_KEYS: &[&str] = &[
    "ALEO_NETWORK",
    "ALEO_VIEW_KEY_FILE",
    "ALEO_PRIVATE_KEY_FILE",
    "SCAN_START_BLOCK",
    "SCAN_SYNC_POLL_INTERVAL_MS",
    "SCAN_SYNC_TIMEOUT_MS",
    "SCAN_SUPPORTED_RECORDS",
    "RECORD_STORE_FILE",
    "RECORD_STORE_PRIVATE",
    "DECRYPTED_RECORD_STORE_FILE",
    "RECORD_PROGRAM",
    "RECORD_NAME",
    "AUTOJOIN_CREDITS",
    "AUTOJOIN_USDCX",
    "AUTOJOIN_ARC20_ETH",
    "AUTOJOIN_ARC20_SOL",
    "AUTOJOIN_ARC20_WBTC",
    // Accepted only so configs created by earlier CLI builds continue to load.
    "DELEGATED_PROVING_URL",
    "DELEGATED_PROVING_TOKEN_FILE",
    "AUTOJOIN_POLL_INTERVAL_MS",
    "AUTOJOIN_TIMEOUT_MS",
    "CLI_INTERVAL_SECONDS",
    "CLI_LOG_LEVEL",
    "CLI_LOG_FILE",
    "CLI_MODE",
];

pub struct RuntimeConfig {
    pub bot: Config,
    pub interval_seconds: u64,
    pub log_level: LogLevel,
    pub log_file: Option<std::path::PathBuf>,
}

pub fn init(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; use --force to replace it",
            path.display()
        );
    }
    println!("{}", ui::heading("Autojoin CLI setup"));
    println!("{} {}", ui::muted("Configuration:"), path.display());
    println!(
        "{}\n",
        ui::muted("Keys can be pasted securely or loaded from an existing protected file.")
    );

    let network = prompt_choice("Network", &["mainnet", "testnet"], "mainnet")?;
    let mode = prompt_choice("Operating mode", &["autojoin", "scan-only"], "autojoin")?;
    let key_kind = if mode == "autojoin" {
        println!(
            "{}",
            ui::muted(
                "Autojoin signs locally, so a private key is required; its view key is derived in memory."
            )
        );
        "private".to_owned()
    } else {
        prompt_choice("Account key", &["view", "private"], "view")?
    };
    let key_method = prompt_choice("Provide key by", &["paste", "file"], "paste")?;
    let key_path = configure_key(path, &network, &key_kind, &key_method)?;
    let start_block = prompt_u64("Scanner start block", 0)?;
    let record_store = prompt("Ciphertext record snapshot (blank to disable)")?;
    let private_ciphertexts = if record_store.is_empty() {
        None
    } else {
        Some(prompt_bool(
            "Restrict ciphertext snapshot to its owner",
            true,
        )?)
    };
    let decrypted_store = prompt("Decrypted record snapshot (blank to disable)")?;

    let mut values = BTreeMap::new();
    values.insert("ALEO_NETWORK", network);
    values.insert("CLI_MODE", mode.clone());
    values.insert(
        if key_kind == "private" {
            "ALEO_PRIVATE_KEY_FILE"
        } else {
            "ALEO_VIEW_KEY_FILE"
        },
        key_path,
    );
    values.insert("SCAN_START_BLOCK", start_block.to_string());
    if !record_store.is_empty() {
        values.insert("RECORD_STORE_FILE", record_store);
        values.insert(
            "RECORD_STORE_PRIVATE",
            private_ciphertexts.unwrap_or(true).to_string(),
        );
    }
    if !decrypted_store.is_empty() {
        values.insert("DECRYPTED_RECORD_STORE_FILE", decrypted_store);
    }

    if mode == "autojoin" {
        loop {
            let mut any_autojoin = false;
            println!("\n{}", ui::heading("Assets to consolidate"));
            for (label, name) in [
                ("ALEO credits", "AUTOJOIN_CREDITS"),
                ("USDCx", "AUTOJOIN_USDCX"),
                ("ARC20 ETH", "AUTOJOIN_ARC20_ETH"),
                ("ARC20 SOL", "AUTOJOIN_ARC20_SOL"),
                ("ARC20 wBTC", "AUTOJOIN_ARC20_WBTC"),
            ] {
                let enabled = prompt_bool(&format!("Enable {label} autojoin"), false)?;
                values.insert(name, enabled.to_string());
                any_autojoin |= enabled;
            }
            if any_autojoin {
                break;
            }
            println!(
                "{}",
                ui::warning("Select at least one asset for autojoin mode.")
            );
        }
    }
    if mode == "scan-only" {
        let scope = prompt_choice(
            "Records to scan",
            &["supported", "all", "custom"],
            "supported",
        )?;
        match scope.as_str() {
            "supported" => {
                values.insert("SCAN_SUPPORTED_RECORDS", "true".to_owned());
            }
            "custom" => {
                values.insert("RECORD_PROGRAM", prompt_required("Record program")?);
                values.insert("RECORD_NAME", prompt_required("Record name")?);
            }
            "all" => {}
            _ => unreachable!("prompt_choice validates the scan scope"),
        }
    }
    values.insert(
        "CLI_INTERVAL_SECONDS",
        prompt_positive_u64("Seconds between completed passes", 60)?.to_string(),
    );
    values.insert(
        "CLI_LOG_LEVEL",
        prompt_choice(
            "Logging verbosity",
            &["off", "error", "warn", "info", "debug", "trace"],
            "info",
        )?,
    );
    let log_file = prompt("Log file (blank uses stderr or the background sidecar)")?;
    if !log_file.is_empty() {
        values.insert("CLI_LOG_FILE", log_file);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    writeln!(
        file,
        "# Paths only: do not place key or token contents in this file."
    )?;
    for (name, value) in values {
        validate_value(&value)?;
        writeln!(file, "{name}={value}")?;
    }
    file.sync_all()?;
    println!("{}", ui::success("Configuration written with mode 0600."));
    println!("{}", ui::muted("Run `autojoin-cli once` to verify it."));
    Ok(())
}

pub fn load(path: &Path) -> Result<RuntimeConfig> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut values = BTreeMap::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (name, value) = trimmed
            .split_once('=')
            .with_context(|| format!("{}:{} must use NAME=VALUE", path.display(), index + 1))?;
        if !CONFIG_KEYS.contains(&name) {
            bail!(
                "{}:{} contains unknown setting {name}",
                path.display(),
                index + 1
            );
        }
        validate_value(value)?;
        values.insert(name.to_owned(), value.to_owned());
    }
    let mode = values.remove("CLI_MODE");
    values.remove("DELEGATED_PROVING_URL");
    values.remove("DELEGATED_PROVING_TOKEN_FILE");
    let any_autojoin = [
        "AUTOJOIN_CREDITS",
        "AUTOJOIN_USDCX",
        "AUTOJOIN_ARC20_ETH",
        "AUTOJOIN_ARC20_SOL",
        "AUTOJOIN_ARC20_WBTC",
    ]
    .iter()
    .any(|name| values.get(*name).is_some_and(|value| value == "true"));
    match mode.as_deref() {
        Some("autojoin") if !any_autojoin => {
            bail!("CLI_MODE=autojoin requires at least one AUTOJOIN_* family")
        }
        Some("scan-only") if any_autojoin => {
            bail!("CLI_MODE=scan-only cannot enable an AUTOJOIN_* family")
        }
        Some("autojoin" | "scan-only") | None => {}
        Some(_) => bail!("CLI_MODE must be autojoin or scan-only"),
    }
    let interval_seconds = values
        .remove("CLI_INTERVAL_SECONDS")
        .unwrap_or_else(|| "60".into())
        .parse::<u64>()
        .context("CLI_INTERVAL_SECONDS must be a positive integer")?;
    if interval_seconds == 0 {
        bail!("CLI_INTERVAL_SECONDS must be a positive integer");
    }
    let log_level = values
        .remove("CLI_LOG_LEVEL")
        .unwrap_or_else(|| "info".into())
        .parse()?;
    let log_file = values.remove("CLI_LOG_FILE").map(std::path::PathBuf::from);
    Ok(RuntimeConfig {
        bot: Config::from_values(&values)?,
        interval_seconds,
        log_level,
        log_file,
    })
}

fn validate_value(value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0']) {
        bail!("configuration values cannot contain control characters");
    }
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{}: ", ui::prompt(label));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

fn prompt_secret(label: &str) -> Result<Zeroizing<String>> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        bail!("secure key paste requires an interactive terminal; choose the file option instead");
    }
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
        return Err(io::Error::last_os_error()).context("failed to protect terminal input");
    }
    let mut protected = original;
    protected.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &protected) } != 0 {
        return Err(io::Error::last_os_error()).context("failed to disable terminal echo");
    }
    let _guard = EchoGuard(original);
    print!("{label} (input hidden): ");
    io::stdout().flush()?;
    let mut value = Zeroizing::new(String::new());
    let bytes_read = io::stdin().read_line(&mut value)?;
    println!();
    if bytes_read == 0 {
        bail!("key input was closed");
    }
    Ok(value)
}

fn configure_key(
    config_path: &Path,
    network: &str,
    key_kind: &str,
    method: &str,
) -> Result<String> {
    if method == "paste" {
        let key = loop {
            let key = prompt_secret(&format!("Paste {key_kind} key"))?;
            if key.trim().is_empty() {
                println!(
                    "{}",
                    ui::warning("The key cannot be empty. Please try again.")
                );
                continue;
            }
            if validate_account_key(network, key_kind, key.trim()).is_ok() {
                break key;
            }
            println!(
                "{}",
                ui::warning(&format!(
                    "That is not a valid {network} {key_kind} key. Please try again."
                ))
            );
        };
        let default_path = make_absolute(&default_key_path(config_path, key_kind))?;
        let default = path_config_value(&default_path)?;
        loop {
            let destination = make_absolute(Path::new(&prompt_default(
                "Save protected key file",
                &default,
            )?))?;
            if destination.exists() {
                println!(
                    "{}",
                    ui::warning(
                        "That file already exists. Choose a new path or restart using the file option."
                    )
                );
                continue;
            }
            write_secret_file(&destination, key.trim())?;
            println!("{}", ui::success("Key saved with mode 0600."));
            return path_config_value(&destination);
        }
    }

    loop {
        let existing = make_absolute(Path::new(&prompt_required(&format!(
            "Existing {key_kind} key file"
        ))?))?;
        match crate::read_secure_key_file(&existing) {
            Ok(key) if validate_account_key(network, key_kind, key.trim()).is_ok() => {
                return path_config_value(&existing);
            }
            Ok(_) => println!(
                "{}",
                ui::warning(&format!(
                    "That file does not contain a valid {network} {key_kind} key."
                ))
            ),
            Err(error) => println!(
                "{}",
                ui::warning(&format!("Cannot use that key file: {error}"))
            ),
        }
    }
}

struct EchoGuard(libc::termios);

impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
        }
    }
}

fn default_key_path(config_path: &Path, key_kind: &str) -> PathBuf {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent.join(format!("account.{key_kind}key"))
}

fn make_absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    Ok(std::env::current_dir()
        .context("failed to determine the current directory")?
        .join(path))
}

fn path_config_value(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .context("key file path must be valid UTF-8")
}

fn write_secret_file(path: &Path, secret: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| {
            format!(
                "failed to create protected key file {}; choose a new path if it already exists",
                path.display()
            )
        })?;
    writeln!(file, "{secret}")?;
    file.sync_all()?;
    Ok(())
}

fn validate_account_key(network: &str, key_kind: &str, key: &str) -> Result<()> {
    let valid = match (network, key_kind) {
        ("mainnet", "private") => key.parse::<PrivateKey<MainnetV0>>().map(|_| ()),
        ("testnet", "private") => key.parse::<PrivateKey<TestnetV0>>().map(|_| ()),
        ("mainnet", "view") => key.parse::<ViewKey<MainnetV0>>().map(|_| ()),
        ("testnet", "view") => key.parse::<ViewKey<TestnetV0>>().map(|_| ()),
        _ => unreachable!("choices are validated before key input"),
    };
    valid.map_err(|_| anyhow::anyhow!("invalid {network} {key_kind} key"))
}

fn prompt_required(label: &str) -> Result<String> {
    loop {
        let value = prompt(label)?;
        if !value.is_empty() {
            return Ok(value);
        }
        println!("{}", ui::warning("A value is required."));
    }
}

fn prompt_default(label: &str, default: &str) -> Result<String> {
    let value = prompt(&format!("{label} [{default}]"))?;
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value
    })
}

fn prompt_choice(label: &str, choices: &[&str], default: &str) -> Result<String> {
    loop {
        let value = prompt_default(&format!("{label} ({})", choices.join("/")), default)?;
        if choices.contains(&value.as_str()) {
            return Ok(value);
        }
        println!(
            "{}",
            ui::warning(&format!("Choose one of: {}", choices.join(", ")))
        );
    }
}

fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        match prompt(&format!("{label} [{hint}]"))?
            .to_ascii_lowercase()
            .as_str()
        {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("{}", ui::warning("Enter yes or no.")),
        }
    }
}

fn prompt_u64(label: &str, default: u64) -> Result<u64> {
    loop {
        match prompt_default(label, &default.to_string())?.parse() {
            Ok(value) => return Ok(value),
            Err(_) => println!("{}", ui::warning("Enter a non-negative integer.")),
        }
    }
}

fn prompt_positive_u64(label: &str, default: u64) -> Result<u64> {
    loop {
        let value = prompt_u64(label, default)?;
        if value > 0 {
            return Ok(value);
        }
        println!("{}", ui::warning("Enter a positive integer."));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn config_values_reject_line_injection() {
        assert!(validate_value("/safe/key").is_ok());
        assert!(validate_value("/safe/key\nEVIL=value").is_err());
    }

    #[test]
    fn validates_keys_for_the_selected_network() {
        let private_key = PrivateKey::<MainnetV0>::new(&mut rand::rng()).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();
        assert!(validate_account_key("mainnet", "private", &private_key.to_string()).is_ok());
        assert!(validate_account_key("mainnet", "view", &view_key.to_string()).is_ok());
        assert!(validate_account_key("mainnet", "private", "not-a-key").is_err());
    }

    #[test]
    fn pasted_keys_are_written_owner_only() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("autojoin-cli-key-{}-{unique}", std::process::id()));
        let path = directory.join("account.privatekey");
        write_secret_file(&path, "secret-value").unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            &*crate::read_secure_key_file(&path).unwrap(),
            "secret-value\n"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn relative_key_paths_are_made_absolute() {
        let relative = Path::new("keys/account.privatekey");
        let absolute = make_absolute(relative).unwrap();

        assert!(absolute.is_absolute());
        assert_eq!(absolute, std::env::current_dir().unwrap().join(relative));
        assert_eq!(make_absolute(&absolute).unwrap(), absolute);
    }
}
