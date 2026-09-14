use anyhow::{Context, Result};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    const fn label(self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.label().to_ascii_lowercase())
    }
}

impl FromStr for LogLevel {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => anyhow::bail!("CLI_LOG_LEVEL must be off, error, warn, info, debug, or trace"),
        }
    }
}

struct Logger {
    level: LogLevel,
    output: Mutex<Box<dyn Write + Send>>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub fn init(level: LogLevel, file: Option<&Path>) -> Result<()> {
    let output: Box<dyn Write + Send> = match file {
        Some(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("failed to open log file {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            Box::new(file)
        }
        None => Box::new(io::stderr()),
    };
    LOGGER
        .set(Logger {
            level,
            output: Mutex::new(output),
        })
        .map_err(|_| anyhow::anyhow!("logging is already initialized"))?;
    Ok(())
}

pub fn event(level: LogLevel, args: fmt::Arguments<'_>) {
    let Some(logger) = LOGGER.get() else { return };
    if level == LogLevel::Off || level > logger.level {
        return;
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    if let Ok(mut output) = logger.output.lock() {
        let _ = writeln!(
            output,
            "[{}.{:03}] {:<5} {}",
            timestamp.as_secs(),
            timestamp.subsec_millis(),
            level.label(),
            args
        );
        let _ = output.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_levels_are_strict_and_ordered() {
        assert_eq!("off".parse::<LogLevel>().unwrap(), LogLevel::Off);
        assert_eq!("TRACE".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert!("verbose".parse::<LogLevel>().is_err());
        assert!(LogLevel::Error < LogLevel::Debug);
    }
}
