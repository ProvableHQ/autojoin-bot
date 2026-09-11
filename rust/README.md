# Rust implementation

The Rust client talks directly to the scanner HTTP API and uses the exact
registration wire format from `ProvableHQ/record-scanning-service`.

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
- `RECORD_PROGRAM` and `RECORD_NAME`: narrow the returned record set.
- `RECORD_STORE_PRIVATE`: defaults to `true`, enforcing an owner-only file and
  protected parent. Set to `false` when ownership disclosure is acceptable.
- `DECRYPTED_RECORD_STORE_FILE`: optional separate owner-only snapshot that
  includes decrypted records for later transaction construction.

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
