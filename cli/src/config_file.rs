use crate::{Config, LogLevel};
use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const CONFIG_KEYS: &[&str] = &[
    "ALEO_NETWORK",
    "ALEO_VIEW_KEY_FILE",
    "ALEO_PRIVATE_KEY_FILE",
    "SCAN_START_BLOCK",
    "SCAN_SYNC_POLL_INTERVAL_MS",
    "SCAN_SYNC_TIMEOUT_MS",
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
    "DELEGATED_PROVING_URL",
    "DELEGATED_PROVING_TOKEN_FILE",
    "AUTOJOIN_POLL_INTERVAL_MS",
    "AUTOJOIN_TIMEOUT_MS",
    "CLI_INTERVAL_SECONDS",
    "CLI_LOG_LEVEL",
    "CLI_LOG_FILE",
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
    println!("Creating {}", path.display());
    println!("Enter paths to secret files, never private/view keys themselves.\n");

    let network = prompt_choice("Network", &["testnet", "mainnet"], "testnet")?;
    let key_kind = prompt_choice("Key type", &["view", "private"], "view")?;
    let key_path = prompt_required(&format!("Path to {key_kind} key file"))?;
    let start_block = prompt_u64("Scanner start block", 0)?;
    let record_store = prompt_default(
        "Ciphertext record store",
        &format!("./records-{network}.json"),
    )?;
    let decrypted_store = prompt("Decrypted record store (blank to disable)")?;
    let private_ciphertexts = prompt_bool("Restrict ciphertext store to its owner", false)?;

    let mut values = BTreeMap::new();
    values.insert("ALEO_NETWORK", network);
    values.insert(
        if key_kind == "private" {
            "ALEO_PRIVATE_KEY_FILE"
        } else {
            "ALEO_VIEW_KEY_FILE"
        },
        key_path,
    );
    values.insert("SCAN_START_BLOCK", start_block.to_string());
    values.insert("RECORD_STORE_FILE", record_store);
    values.insert("RECORD_STORE_PRIVATE", private_ciphertexts.to_string());
    if !decrypted_store.is_empty() {
        values.insert("DECRYPTED_RECORD_STORE_FILE", decrypted_store);
    }

    let record_program = prompt("Record program filter (blank for all)")?;
    let record_name = prompt("Record name filter (blank for all)")?;
    if !record_program.is_empty() {
        values.insert("RECORD_PROGRAM", record_program);
    }
    if !record_name.is_empty() {
        values.insert("RECORD_NAME", record_name);
    }

    let mut any_autojoin = false;
    if key_kind == "private" {
        for (label, name) in [
            ("ALEO credits", "AUTOJOIN_CREDITS"),
            ("USDCx", "AUTOJOIN_USDCX"),
            ("ARC20 ETH", "AUTOJOIN_ARC20_ETH"),
            ("ARC20 SOL", "AUTOJOIN_ARC20_SOL"),
            ("ARC20 WBTC", "AUTOJOIN_ARC20_WBTC"),
        ] {
            let enabled = prompt_bool(&format!("Enable {label} autojoin"), false)?;
            values.insert(name, enabled.to_string());
            any_autojoin |= enabled;
        }
    }
    if any_autojoin {
        values.insert(
            "DELEGATED_PROVING_URL",
            prompt_required("Delegated proving URL")?,
        );
        let token = prompt("Delegated proving token file (blank if not required)")?;
        if !token.is_empty() {
            values.insert("DELEGATED_PROVING_TOKEN_FILE", token);
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
    println!("Configuration written with mode 0600. Run `autojoin-cli once` to verify it.");
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
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

fn prompt_required(label: &str) -> Result<String> {
    loop {
        let value = prompt(label)?;
        if !value.is_empty() {
            return Ok(value);
        }
        println!("A value is required.");
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
        println!("Choose one of: {}", choices.join(", "));
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
            _ => println!("Enter yes or no."),
        }
    }
}

fn prompt_u64(label: &str, default: u64) -> Result<u64> {
    loop {
        match prompt_default(label, &default.to_string())?.parse() {
            Ok(value) => return Ok(value),
            Err(_) => println!("Enter a non-negative integer."),
        }
    }
}

fn prompt_positive_u64(label: &str, default: u64) -> Result<u64> {
    loop {
        let value = prompt_u64(label, default)?;
        if value > 0 {
            return Ok(value);
        }
        println!("Enter a positive integer.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_values_reject_line_injection() {
        assert!(validate_value("/safe/key").is_ok());
        assert!(validate_value("/safe/key\nEVIL=value").is_err());
    }
}
