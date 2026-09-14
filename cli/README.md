# Autojoin CLI

This Unix-oriented CLI is a standalone implementation with interactive
configuration and continuous process management. It contains its own scanner,
record, storage, and delegated-proving code and has no compile-time or runtime
dependency on the one-shot Rust or JavaScript examples.

```sh
cargo build --release
./target/release/autojoin-cli init
./target/release/autojoin-cli once
./target/release/autojoin-cli run

# Optional detached mode
./target/release/autojoin-cli start
./target/release/autojoin-cli status
./target/release/autojoin-cli stop
```

All commands accept `--config PATH`; the default is
`~/.config/autojoin-bot/config.env`. `init --force` replaces an existing
configuration.

During `init`, choose whether to paste a private/view key or use an existing
protected key file. Pasted input is hidden by disabling terminal echo,
validated for the selected network, and written to a new mode-`0600` file. The
CLI refuses to overwrite an existing key file. When the file option is chosen,
the existing file is checked before setup continues.

The configuration contains only the resulting key-file path, never the key
itself, and is also written with mode `0600`. Every subsequent key read rejects
symlinks, files not owned by the current user, and group/world permissions.

`run` executes one pass at a time and waits `CLI_INTERVAL_SECONDS` after each
completed pass. A failed pass is reported and retried after that interval.
`start` runs that loop in a detached session and sends output to the `.log`
sidecar beside the configuration; `.pid` tracks the worker. SIGINT and SIGTERM
cancel an in-progress pass and shut the worker down cleanly.

## Logging

`init` prompts for an optional log level and log file. The corresponding
configuration settings are:

- `CLI_LOG_LEVEL=off|error|warn|info|debug|trace` (`info` by default).
- `CLI_LOG_FILE=/path/to/autojoin.log` to select a file. When omitted,
  foreground commands log to stderr and detached mode logs to the `.log`
  sidecar beside the configuration.

The tiers are cumulative: `error` reports failed passes; `warn` adds scanner
registration recovery; `info` adds lifecycle and pass summaries; `debug` adds
scanner registration and join-batch progress; and `trace` adds synchronization,
pagination, and tag-check polling. `off` disables operational events. The
one-shot JSON result from `once` remains on stdout independently of log level.

Log files are created or corrected to mode `0600`. Events never include key or
token contents, decrypted records, ciphertexts, record tags, or scanner UUIDs.
Record and join counts are included at `info` and above.

Detached mode is intentionally lightweight. Use `autojoin-cli run` under
systemd, launchd, or a container orchestrator when boot persistence, log
rotation, resource limits, or automatic supervisor restart are required.
