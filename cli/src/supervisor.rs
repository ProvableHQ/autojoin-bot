use crate::run_once;
use crate::{
    LogLevel, config_file,
    logging::{self, event},
    ui,
    workflow::RunSummary,
};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    io,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
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

const PID_FILE_PREFIX: &str = "autojoin-cli-pid-v1 ";
const STOP_REQUEST: &str = "autojoin-cli-stop-v1\n";

struct PidGuard {
    pid_path: PathBuf,
    stop_path: PathBuf,
    _file: File,
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        // Remove the pathname while the lock is still held. This prevents a
        // second worker from acquiring this inode between unlock and cleanup.
        let _ = fs::remove_file(&self.stop_path);
        let _ = fs::remove_file(&self.pid_path);
    }
}

pub async fn once(config_path: &Path) -> Result<()> {
    let runtime = config_file::load(config_path)?;
    if let Some(path) = &runtime.log_file {
        eprintln!(
            "{}",
            ui::muted(&format!("Operational log: {}", path.display()))
        );
    }
    logging::init(runtime.log_level, runtime.log_file.as_deref())?;
    let _guard = claim_pid(&sidecar(config_path, "pid"), &sidecar(config_path, "stop"))?;
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
    let stop_path = sidecar(config_path, "stop");
    let _guard = claim_pid(&sidecar(config_path, "pid"), &stop_path)?;
    let mut stop_request = Box::pin(wait_for_stop_request(stop_path));
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    if foreground {
        println!(
            "{} {}",
            ui::success("Continuous worker started."),
            ui::muted("Press Ctrl-C to stop.")
        );
        match log_file {
            Some(path) => println!(
                "{}",
                ui::muted(&format!("Operational log: {}", path.display()))
            ),
            None => println!("{}", ui::muted("Operational log: stderr")),
        }
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
            _ = stop_request.as_mut() => None,
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
            _ = stop_request.as_mut() => false,
        };
        if !should_continue {
            break;
        }
    }
    if foreground {
        println!("{}", ui::success("Continuous worker stopped."));
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
                "{} {}",
                ui::success(&format!("Background worker started (PID {pid}).")),
                ui::muted(&format!("Log: {}", log_path.display()))
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
    let Some(_pid) = live_pid(&pid_path)? else {
        bail!("background worker is not running");
    };
    write_stop_request(&sidecar(config, "stop"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if live_pid(&pid_path)?.is_none() {
            println!("{}", ui::success("Background worker stopped."));
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    bail!("worker did not acknowledge the stop request within 10 seconds")
}

pub fn status(config: &Path) -> Result<()> {
    let runtime = config_file::load(config)?;
    let log_path = runtime.log_file.unwrap_or_else(|| sidecar(config, "log"));
    match live_pid(&sidecar(config, "pid"))? {
        Some(pid) => {
            println!("{}", ui::success(&format!("running (PID {pid})")));
            println!(
                "{}",
                ui::muted(&format!(
                    "Log: {} (level: {})",
                    log_path.display(),
                    runtime.log_level
                ))
            );
        }
        None => println!("{}", ui::muted("stopped")),
    }
    Ok(())
}

fn claim_pid(path: &Path, stop_path: &Path) -> Result<PidGuard> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_pid_file(&file, path)?;
    if !try_lock_pid_file(&file)? {
        let pid = read_locked_pid(&mut file)?;
        bail!("worker is already running (PID {pid})");
    }

    // Older builds wrote a bare PID and held no lock. If such a process still
    // exists, fail closed: its identity cannot be established safely.
    let previous = read_pid_file(&mut file)?;
    reject_legacy_pid_file(&previous)?;
    remove_stale_stop_request(stop_path)?;

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(file, "{PID_FILE_PREFIX}{}", std::process::id())?;
    file.sync_all()?;
    Ok(PidGuard {
        pid_path: path.to_owned(),
        stop_path: stop_path.to_owned(),
        _file: file,
    })
}

fn live_pid(path: &Path) -> Result<Option<libc::pid_t>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_pid_file(&file, path)?;
    if try_lock_pid_file(&file)? {
        // No worker owns this file. The lock is released when `file` drops.
        let previous = read_pid_file(&mut file)?;
        reject_legacy_pid_file(&previous)?;
        return Ok(None);
    }
    Ok(Some(read_locked_pid(&mut file)?))
}

fn try_lock_pid_file(file: &File) -> Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error.into())
    }
}

fn validate_pid_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("PID file {} is not a regular file", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("PID file {} is not owned by this user", path.display());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("PID file {} must have mode 0600", path.display());
    }
    if metadata.len() > 128 {
        bail!("PID file {} is unexpectedly large", path.display());
    }
    Ok(())
}

fn read_pid_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut value = String::new();
    file.take(129).read_to_string(&mut value)?;
    Ok(value)
}

fn read_locked_pid(file: &mut File) -> Result<libc::pid_t> {
    let value = read_pid_file(file)?;
    let pid = value
        .trim()
        .strip_prefix(PID_FILE_PREFIX)
        .context("locked PID file has an invalid or legacy format; refusing to trust it")?
        .parse::<libc::pid_t>()
        .context("locked PID file contains an invalid PID")?;
    if pid <= 0 {
        bail!("locked PID file contains an invalid PID");
    }
    Ok(pid)
}

fn reject_legacy_pid_file(value: &str) -> Result<()> {
    let value = value.trim();
    if !value.is_empty() && !value.starts_with(PID_FILE_PREFIX) {
        bail!(
            "an unlocked legacy PID file cannot be verified safely; confirm no older worker is running, then remove it"
        );
    }
    Ok(())
}

fn remove_stale_stop_request(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_stop_request(path: &Path) -> Result<()> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    file.write_all(STOP_REQUEST.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

async fn wait_for_stop_request(path: PathBuf) {
    while !path.exists() {
        sleep(Duration::from_millis(100)).await;
    }
}

fn sidecar(config: &Path, suffix: &str) -> PathBuf {
    let mut value = config.as_os_str().to_owned();
    value.push(format!(".{suffix}"));
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn control_paths(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "autojoin-supervisor-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let pid = directory.join("worker.pid");
        let stop = directory.join("worker.stop");
        (directory, pid, stop)
    }

    #[test]
    fn sidecars_do_not_replace_the_config_extension() {
        assert_eq!(
            sidecar(Path::new("/tmp/config.env"), "pid"),
            PathBuf::from("/tmp/config.env.pid")
        );
    }

    #[test]
    fn pid_lock_identifies_the_worker_and_releases_on_drop() {
        let (directory, pid_path, stop_path) = control_paths("lock");
        let guard = claim_pid(&pid_path, &stop_path).unwrap();

        assert_eq!(
            live_pid(&pid_path).unwrap(),
            Some(std::process::id() as libc::pid_t)
        );
        drop(guard);
        assert_eq!(live_pid(&pid_path).unwrap(), None);
        assert!(!pid_path.exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unlocked_pid_file_is_stale_even_if_its_number_was_reused() {
        let (directory, pid_path, _stop_path) = control_paths("stale");
        fs::write(
            &pid_path,
            format!("{PID_FILE_PREFIX}{}\n", std::process::id()),
        )
        .unwrap();
        fs::set_permissions(&pid_path, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(live_pid(&pid_path).unwrap(), None);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_pid_file_fails_closed() {
        let (directory, pid_path, stop_path) = control_paths("legacy");
        fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();
        fs::set_permissions(&pid_path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = claim_pid(&pid_path, &stop_path)
            .err()
            .expect("an unverifiable live legacy PID must be rejected");
        assert!(error.to_string().contains("unlocked legacy PID file"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn cooperative_stop_request_wakes_the_worker() {
        let (directory, pid_path, stop_path) = control_paths("stop");
        let guard = claim_pid(&pid_path, &stop_path).unwrap();

        write_stop_request(&stop_path).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_stop_request(stop_path.clone()),
        )
        .await
        .expect("worker did not observe its stop request");

        drop(guard);
        assert!(!stop_path.exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
