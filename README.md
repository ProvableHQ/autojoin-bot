# autojoin-bot

Programmatic Aleo autojoin bot implementations:

- [`js/`](js/README.md) — JavaScript using `@provablehq/sdk`.
- [`rust/`](rust/README.md) — Rust using the scanner's HTTP wire contract.

Both securely load either a view key or private key from an owner-only file,
register the derived view key through the encrypted one-time-key flow, fetch
owned records with `unspent: true`, and verify their tags against
`/records/tags`. The resulting ciphertexts and input-selection metadata are
stored in an atomic local snapshot without decrypted plaintext. Owner-only
ciphertext storage is the default but can be relaxed; an optional separate
decrypted-record snapshot is always owner-only.

Both implementations can optionally consolidate ALEO credits records using
the deployed `autojoin_credits_2_10.aleo`, `autojoin_credits_11_14.aleo`, and
`autojoin_credits_15_16.aleo` programs. They authorize locally, delegate all
proof generation and fee payment, broadcast through the proving service, and
rescan between batches so a set larger than 16 is reduced safely and
iteratively.

USDCx consolidation is also supported for `usdcx_stablecoin.aleo/Token`
(mainnet) and `test_usdcx_stablecoin.aleo/Token` (testnet), using the
network-specific `aj_usdcx_stablecoin_*` / `test_aj_usdcx_stablecoin_*`
program families.

ARC20 consolidation is supported for `arc20_eth.aleo/Token`,
`arc20_sol.aleo/Token`, and `arc20_wbtc.aleo/Token` on mainnet and the matching
`test_*` token programs on testnet. It calls `main_aj_arc20_2_15.aleo/join_N`
or `test_aj_arc20_2_15.aleo/join_N`, passing the network-specific token program
identifier as the first public input and explicitly loading the dynamically
dispatched token program and its imports before authorization.
