# Rust implementation

The Rust client talks directly to the scanner HTTP API and uses the exact
registration wire format from `ProvableHQ/record-scanning-service`.

Code is organized by responsibility: `config.rs` handles environment
configuration, `secret.rs` reads protected inputs, `scanner.rs` implements the
record-scanner protocol, `records.rs` owns record models and selection,
`autojoin.rs` builds and submits delegated proving requests, `store.rs` manages
atomic snapshots, and `network.rs` contains network selection. `lib.rs` only
declares and re-exports those modules.

```sh
cp .env.example .env
umask 077
printf '%s\n' 'AViewKey1...' > /secure/path/account.viewkey
chmod 600 /secure/path/account.viewkey
set -a; source .env; set +a
cargo run --release
```

Required variables:

- Exactly one of `ALEO_VIEW_KEY_FILE` or `ALEO_PRIVATE_KEY_FILE`: absolute path
  to an account key file. It must be a regular file owned by the current user,
  grant no group/other permissions, and not be a symlink. If a private key is
  given, its view key is derived in process. Mode `0600` is recommended.
- `RECORD_STORE_FILE`: destination for the local unspent-record snapshot. Its
  default privacy behavior is controlled by `RECORD_STORE_PRIVATE`.

Optional variables:

- `ALEO_NETWORK`: `testnet` (default) or `mainnet`.
- `SCAN_START_BLOCK`: first block to scan; defaults to `0`.
- `SCAN_SYNC_POLL_INTERVAL_MS` and `SCAN_SYNC_TIMEOUT_MS`: polling interval
  (5 seconds) and timeout (5 minutes) for initial scanner synchronization.
  Increase the timeout for accounts with a long scan history.
- `RECORD_PROGRAM` and `RECORD_NAME`: narrow the returned record set.
- `RECORD_STORE_PRIVATE`: defaults to `true`, enforcing an owner-only file and
  protected parent. Set to `false` when ownership disclosure is acceptable.
- `DECRYPTED_RECORD_STORE_FILE`: optional separate owner-only snapshot that
  includes decrypted records for later transaction construction.
- `AUTOJOIN_CREDITS`: defaults to `false`. When `true`, repeatedly consolidates
  all unspent `credits.aleo/credits` records and broadcasts through delegated
  proving. A private key and `DELEGATED_PROVING_URL` are then required.
- `AUTOJOIN_USDCX`: defaults to `false`. When `true`, applies the same
  iterative delegated-proving flow to USDCx `Token` records.
- `AUTOJOIN_ARC20_ETH`, `AUTOJOIN_ARC20_SOL`, and `AUTOJOIN_ARC20_WBTC`:
  independently enable consolidation for those ARC20 `Token` records on the
  selected network.
- `DELEGATED_PROVING_TOKEN_FILE`: optional owner-only file containing the
  prover bearer token. The token is never accepted directly from the command
  line or environment.
- `AUTOJOIN_POLL_INTERVAL_MS` and `AUTOJOIN_TIMEOUT_MS`: scanner polling
  interval (5 seconds) and per-join timeout (5 minutes).

Before the first owned-record read, the client polls `/status` until it reports
`synced: true`. This also applies in scan-only mode. Zero or one records are
valid final results only after that wait. A timeout or status error exits
before any autojoin is authorized or an existing record snapshot is replaced.
The timeout covers status requests and polling delays. HTTP 422 triggers one
encrypted re-registration with the configured `SCAN_START_BLOCK` and a retry.
Subsequent scans in the same run use the existing join polling flow.

For 2–10 inputs the client calls `autojoin_credits_2_10.aleo/join_N`; for
11–14 it calls `autojoin_credits_11_14.aleo/join_N`; and for 15–16 it calls
`autojoin_credits_15_16.aleo/join_N`. More than 16 records are reduced in
successive batches of 16. After every accepted delegated broadcast the client
waits until the scanner reports every input tag spent and a new replacement
tag before authorizing the next join.

The caller signs a full authorization locally, including nested
`credits.aleo/join` requests. The authorization is wrapped in the delegated
proving service's canonical JSON `ProvingRequest`, assigned a random 128-bit
job ID, sealed to a one-time `/pubkey`, and sent to `POST /prove` with
`broadcast: true`. The fee is omitted so the configured delegated prover fee
master pays it. snarkVM is used only for local authorization; proof generation
remains delegated.

USDCx uses `usdcx_stablecoin.aleo/Token` on mainnet and
`test_usdcx_stablecoin.aleo/Token` on testnet. Mainnet joins use
`aj_usdcx_stablecoin_{2_10,11_14,15_16}.aleo`; testnet joins use the matching
`test_aj_usdcx_stablecoin_*` program ID. Each calls `join_N` for the selected
batch size. The Rust authorization loader recursively fetches and registers
the stablecoin program's import graph before signing the nested calls.

ARC20 joins use `main_aj_arc20_2_15.aleo/join_N` on mainnet and
`test_aj_arc20_2_15.aleo/join_N` on testnet for batches of 2–15. The public
token identifier literal is also network-specific—for example, `'arc20_eth'`
or `'test_arc20_eth'`—and is prepended to the dynamic record inputs. The Rust
loader explicitly registers the selected token program and its transitive
imports before authorization. Sixteen records are therefore reduced with
`join_15` followed by `join_2`.

The selected endpoint is
`https://edge.provable.com/api/scanner/{mainnet|testnet}`. Edge is used as an
unauthenticated free-tier service; no API key is sent. Results from
`/records/owned` are paginated and their tags are checked in batches against
`/records/tags`. An HTTP 422 during an owned-record read triggers one encrypted
re-registration and retry, matching the scanner's restart contract.

Key material is never accepted directly through an environment variable or
command-line argument. The file is opened with `O_NOFOLLOW | O_CLOEXEC`,
validated through the opened descriptor to avoid path races, bounded to 512
bytes, and held in zeroizing memory while it is parsed.

Each successful scan atomically replaces the ciphertext snapshot with the
current unspent set. It contains public ciphertexts plus selection metadata,
but never plaintext. The default remains private because collecting those
ciphertexts under one UUID reveals ownership; this check can be disabled.

When `DECRYPTED_RECORD_STORE_FILE` is set, a second snapshot includes plaintext
for transaction construction and always requires an owner-only directory and
mode `0600`. Standard output never contains records from either store.
