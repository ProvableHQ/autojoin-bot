mod autojoin;
mod bot_config;
mod config_file;
mod http;
mod logging;
mod network;
mod records;
mod scanner;
mod secret;
mod store;
mod supervisor;
mod ui;
mod workflow;

pub use autojoin::DelegatedProverClient;
pub use bot_config::{Config, KeySource};
pub use logging::LogLevel;
pub use network::AleoNetwork;
pub use records::{RecordFamily, ScanResult, records_for_family};
pub use scanner::ScannerClient;
pub use secret::read_secure_key_file;
pub use store::{RecordStoreOptions, write_record_store};
pub use workflow::run_once;

use anyhow::{Context, Result, bail};
use std::{env, path::PathBuf};

struct Options {
    command: String,
    config: PathBuf,
    force: bool,
    internal_daemon: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = parse_args()?;
    match options.command.as_str() {
        "init" => config_file::init(&options.config, options.force),
        "once" => supervisor::once(&options.config).await,
        "run" => supervisor::run(&options.config, true).await,
        "start" => supervisor::start(&options.config),
        "stop" => supervisor::stop(&options.config).await,
        "status" => supervisor::status(&options.config),
        "__worker" if options.internal_daemon => supervisor::run(&options.config, false).await,
        "help" => {
            print_help();
            Ok(())
        }
        command => bail!("unknown command '{command}' (try 'autojoin-cli help')"),
    }
}

fn parse_args() -> Result<Options> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_owned());
    let mut config = default_config_path()?;
    let mut force = false;
    let mut internal_daemon = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = PathBuf::from(args.next().context("--config requires a path")?),
            "--force" => force = true,
            "--internal-daemon" => internal_daemon = true,
            "-h" | "--help" => {
                return Ok(Options {
                    command: "help".into(),
                    config,
                    force,
                    internal_daemon,
                });
            }
            _ => bail!("unknown option '{arg}'"),
        }
    }
    Ok(Options {
        command,
        config,
        force,
        internal_daemon,
    })
}

fn default_config_path() -> Result<PathBuf> {
    if let Some(root) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(root).join("autojoin-bot/config.env"));
    }
    let home = env::var_os("HOME").context("HOME is not set; pass --config explicitly")?;
    Ok(PathBuf::from(home).join(".config/autojoin-bot/config.env"))
}

fn print_help() {
    println!(
        "autojoin-cli — configure and run the standalone autojoin worker\n\n\
Usage: autojoin-cli <COMMAND> [OPTIONS]\n\n\
Commands:\n  init    Interactively create a configuration\n  once    Run one scan/autojoin pass\n  run     Run continuously in the foreground\n  start   Run continuously as a detached background process\n  stop    Gracefully stop the background process\n  status  Report whether the background process is running\n\n\
Options:\n  --config <PATH>  Configuration file path\n  --force          Replace an existing config (init only)\n\n\
The default config is ~/.config/autojoin-bot/config.env. Logging supports\n\
off, error, warn, info, debug, and trace levels through `init` or the config."
    );
}
