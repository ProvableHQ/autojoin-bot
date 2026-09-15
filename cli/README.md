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

The wizard starts by selecting an operating mode:

- `autojoin` requires a private key and at least one asset family. Its view key
  is derived in memory for scanner operations.
- `scan-only` accepts either key type and defaults to the less-privileged view
  key. It cannot enable autojoin families. Its record scope can be `supported`
  (the default), `all`, or a custom program/record pair.

Autojoin mode derives scanner filters from the selected asset families; it
does not ask for generic record filters. Scan-only `supported` mode scans all
known family pairs: `credits.aleo/credits`, the network-specific USDCx
stablecoin program with record `Token`, and the network-specific ETH, SOL, and
wBTC ARC20 programs with record `Token`. Testnet program IDs receive their
required `test_` prefixes automatically.

Mainnet is the default network both in the wizard and when `ALEO_NETWORK` is
omitted from a hand-written configuration.

Local record snapshots are disabled by default because the record scanner is
the source of truth. During setup, leave both snapshot prompts blank to save no
record files. `RECORD_STORE_FILE` optionally enables a ciphertext-only snapshot;
`DECRYPTED_RECORD_STORE_FILE` independently enables an owner-only snapshot that
also contains decrypted plaintext.

Autojoin always uses the free, unauthenticated Edge delegated-proving service.
The network-specific base URL is selected automatically:

- `https://edge.provable.com/api/prove/mainnet`
- `https://edge.provable.com/api/prove/testnet`

The CLI retrieves the one-time encryption key from `{base}/pubkey` and submits
the encrypted proving request to `{base}/prove`. The wizard does not request a
proving URL, API key, or bearer-token file.

Interactive prompts and lifecycle status use terminal-aware color. ANSI escape
sequences are omitted when output is redirected. Set the standard `NO_COLOR`
environment variable to disable color explicitly.

`run` executes one pass at a time and waits `CLI_INTERVAL_SECONDS` after each
completed pass. A failed pass is reported and retried after that interval.
Each pass derives the scanner UUID locally and checks `/status` first. An
existing scan is allowed to reach `synced: true` without re-registration; a
missing registration is renewed and then held behind the same synchronization
barrier before records are fetched.
`start` runs that loop in a detached session and sends output to the `.log`
sidecar beside the configuration; `.pid` tracks the worker. `status` reports
both the worker PID and its active log path and level. SIGINT and SIGTERM cancel
an in-progress pass and shut the worker down cleanly.

The worker holds an advisory lock on its owner-only PID file for its entire
lifetime. `stop` never signals the numeric PID; it writes an owner-only
cooperative stop request that the locked worker monitors. Unlocked PID files are
treated as stale, so PID reuse cannot cause an unrelated process to be killed.

## Logging

`init` prompts for an optional log level and log file. The corresponding
configuration settings are:

- `CLI_LOG_LEVEL=off|error|warn|info|debug|trace` (`info` by default).
- `CLI_LOG_FILE=/path/to/autojoin.log` to select a file. When omitted,
  foreground commands log to stderr and detached mode logs to the `.log`
  sidecar beside the configuration.

The tiers are cumulative: `error` reports failed passes; `warn` adds scanner
registration recovery; and `info` reports pass lifecycle, view-key registration,
scanner synchronization, record scans, spent filtering, decryption counts,
unspent counts, consolidation batches, delegated-proving acceptance, scanner
observation, and record-store updates. `debug` and `trace` add lower-level
diagnostics such as pagination and tag-check polling. `off` disables operational
events. The one-shot JSON result from `once` remains on stdout independently of
log level.

Log files are created or corrected to mode `0600`. Events never include key or
token contents, decrypted records, ciphertexts, record tags, or scanner UUIDs.
Record and join counts are included at `info` and above.

Detached mode is intentionally lightweight. Use `autojoin-cli run` under
systemd, launchd, or a container orchestrator when boot persistence, log
rotation, resource limits, or automatic supervisor restart are required.
