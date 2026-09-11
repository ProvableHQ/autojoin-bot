# autojoin-bot

Programmatic Aleo autojoin bot implementations:

- [`js/`](js/README.md) — JavaScript using `@provablehq/sdk`.
- [`rust/`](rust/README.md) — Rust using the scanner's HTTP wire contract.

Both securely load either a view key or private key from an owner-only file,
register the derived view key through the encrypted one-time-key flow, fetch
owned records with `unspent: true`, and verify their tags against
`/records/tags`.
