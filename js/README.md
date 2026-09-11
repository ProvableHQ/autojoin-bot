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

Optional variables:

- `ALEO_NETWORK`: `testnet` (default) or `mainnet`.
- `SCAN_START_BLOCK`: first block to scan; defaults to `0`.
- `RECORD_PROGRAM` and `RECORD_NAME`: narrow the returned record set.

The SDK receives `https://edge.provable.com/api/scanner` as its base URL and
appends `/mainnet` or `/testnet` from the selected SDK build. Edge is used as
an unauthenticated free-tier service; no API key is sent.

Key material is never accepted directly through an environment variable or
command-line argument, both of which are more easily exposed through process
inspection, debugging, or accidental logging. The process reads it from an
already-opened, permission-checked descriptor and frees SDK key objects
afterward.
