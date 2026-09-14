use crate::run_once;
use crate::{
    LogLevel, config_file,
    logging::{self, event},
    workflow::RunSummary,
};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, OpenOptions},
    io,
    io::Write,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::sleep,
};

struct PidGuard(PathBuf);

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub async fn once(config_path: &Path) -> Result<()> {
    let runtime = config_file::load(config_path)?;
    logging::init(runtime.log_level, runtime.log_file.as_deref())?;
    let _guard = claim_pid(&sidecar(config_path, "pid"))?;
    event(LogLevel::Debug, format_args!("starting one-time pass"));
    let summary = run_once(&runtime.bot).await?;
    event(
        LogLevel::Info,
        format_args!("{}", completion_message(&summary)),
    );
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

pub async fn run(config_path: &Path, foreground: bool) -> Result<()> {
    let runtime = config_file::load(config_path)?;
    let default_log = (!foreground).then(|| sidecar(config_path, "log"));
    let log_file = runtime.log_file.as_deref().or(default_log.as_deref());
    logging::init(runtime.log_level, log_file)?;
    let _guard = claim_pid(&sidecar(config_path, "pid"))?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    if foreground {
        println!("Continuous worker started; press Ctrl-C to stop.");
    }
    event(
        LogLevel::Info,
        format_args!(
            "worker started network={} interval_seconds={}",
            runtime.bot.network.as_str(),
            runtime.interval_seconds
        ),
    );
    loop {
        let result = tokio::select! {
            result = run_once(&runtime.bot) => Some(result),
            _ = interrupt.recv() => None,
            _ = terminate.recv() => None,
        };
        let Some(result) = result else { break };
        match result {
            Ok(summary) => event(
                LogLevel::Info,
                format_args!("{}", completion_message(&summary)),
            ),
            Err(error) => event(
                LogLevel::Error,
                format_args!(
                    "autojoin pass failed: {error:#}; retrying after {}s",
                    runtime.interval_seconds
                ),
            ),
        }
        let should_continue = tokio::select! {
            _ = sleep(Duration::from_secs(runtime.interval_seconds)) => true,
            _ = interrupt.recv() => false,
            _ = terminate.recv() => false,
        };
        if !should_continue {
            break;
        }
    }
    if foreground {
        println!("Continuous worker stopped.");
    }
    event(LogLevel::Info, format_args!("worker stopped"));
    Ok(())
}

fn completion_message(summary: &RunSummary) -> String {
    format!(
        "pass completed records={} joins={{credits:{},usdcx:{},arc20_eth:{},arc20_sol:{},arc20_wbtc:{}}}",
        summary.record_count,
        summary.credits_joins,
        summary.usdcx_joins,
        summary.arc20_eth_joins,
        summary.arc20_sol_joins,
        summary.arc20_wbtc_joins
    )
}

pub fn start(config: &Path) -> Result<()> {
    let runtime = config_file::load(config)?;
    let pid_path = sidecar(config, "pid");
    if let Some(pid) = live_pid(&pid_path)? {
        bail!("background worker is already running (PID {pid})");
    }
    if pid_path.exists() {
        fs::remove_file(&pid_path)?;
    }
    let log_path = runtime.log_file.unwrap_or_else(|| sidecar(config, "log"));
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))?;
    let error_log = log.try_clone()?;
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("__worker")
        .arg("--internal-daemon")
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = command
        .spawn()
        .context("failed to start background worker")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(pid) = live_pid(&pid_path)? {
            println!(
                "Background worker started (PID {pid}); log: {}",
                log_path.display()
            );
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    bail!(
        "background worker PID {} did not become ready; inspect {}",
        child.id(),
        log_path.display()
    )
}

pub async fn stop(config: &Path) -> Result<()> {
    let pid_path = sidecar(config, "pid");
    let Some(pid) = live_pid(&pid_path)? else {
        bail!("background worker is not running");
    };
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !process_alive(pid) {
            let _ = fs::remove_file(&pid_path);
            println!("Background worker stopped.");
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    bail!("worker did not stop within 10 seconds (PID {pid})")
}

pub fn status(config: &Path) -> Result<()> {
    match live_pid(&sidecar(config, "pid"))? {
        Some(pid) => println!("running (PID {pid})"),
        None => println!("stopped"),
    }
    Ok(())
}

fn claim_pid(path: &Path) -> Result<PidGuard> {
    if let Some(pid) = live_pid(path)? {
        bail!("worker is already running (PID {pid})");
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", std::process::id())?;
    file.sync_all()?;
    Ok(PidGuard(path.to_owned()))
}

fn live_pid(path: &Path) -> Result<Option<libc::pid_t>> {
    let Ok(value) = fs::read_to_string(path) else {
        return Ok(None);
    };
    let pid = value
        .trim()
        .parse::<libc::pid_t>()
        .context("invalid PID file")?;
    Ok(process_alive(pid).then_some(pid))
}

fn process_alive(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn sidecar(config: &Path, suffix: &str) -> PathBuf {
    let mut value = config.as_os_str().to_owned();
    value.push(format!(".{suffix}"));
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecars_do_not_replace_the_config_extension() {
        assert_eq!(
            sidecar(Path::new("/tmp/config.env"), "pid"),
            PathBuf::from("/tmp/config.env.pid")
        );
    }
}
