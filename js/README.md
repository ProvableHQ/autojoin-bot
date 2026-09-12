# JavaScript implementation

Requires Node.js 20 or newer.

```sh
npm install
cp .env.example .env
umask 077
printf '%s\n' 'AViewKey1...' > /secure/path/account.viewkey
chmod 600 /secure/path/account.viewkey
set -a; source .env; set +a
npm start
```

Required variables:

- Exactly one of `ALEO_VIEW_KEY_FILE` or `ALEO_PRIVATE_KEY_FILE`: absolute path
  to an account key file. It must be a regular file owned by the current user,
  grant no group/other access, and not be a symlink. If a private key is given,
  its view key is derived in process. Mode `0600` is recommended.
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
- `AUTOJOIN_CREDITS`: defaults to `false`. When `true`, repeatedly consolidates
  all unspent `credits.aleo/credits` records and broadcasts through delegated
  proving. A private key and `DELEGATED_PROVING_URL` are then required.
- `AUTOJOIN_USDCX`: defaults to `false`. When `true`, applies the same
  iterative delegated-proving flow to USDCx `Token` records.
- `DELEGATED_PROVING_TOKEN_FILE`: optional owner-only file containing the
  prover bearer token. The token is never accepted directly from the command
  line or environment.
- `AUTOJOIN_POLL_INTERVAL_MS` and `AUTOJOIN_TIMEOUT_MS`: scanner polling
  interval (5 seconds) and per-join timeout (5 minutes).

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
master pays it.

USDCx uses `usdcx_stablecoin.aleo/Token` on mainnet and
`test_usdcx_stablecoin.aleo/Token` on testnet. Mainnet joins use
`aj_usdcx_stablecoin_{2_10,11_14,15_16}.aleo`; testnet joins use the matching
`test_aj_usdcx_stablecoin_*` program ID. Each calls `join_N` for the selected
batch size.

The SDK receives `https://edge.provable.com/api/scanner` as its base URL and
appends `/mainnet` or `/testnet` from the selected SDK build. Edge is used as
an unauthenticated free-tier service; no API key is sent.

Key material is never accepted directly through an environment variable or
command-line argument, both of which are more easily exposed through process
inspection, debugging, or accidental logging. The process reads it from an
already-opened, permission-checked descriptor and frees SDK key objects
afterward.

Each successful scan atomically replaces the ciphertext snapshot with the
current unspent set. It contains public ciphertexts plus selection metadata,
but never plaintext. The default remains private because collecting those
ciphertexts under one UUID reveals ownership; this check can be disabled.

When `DECRYPTED_RECORD_STORE_FILE` is set, a second snapshot includes plaintext
for transaction construction and always requires an owner-only directory and
mode `0600`. Standard output never contains records from either store.
