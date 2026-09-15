use std::process::Command;

const AUTOJOIN_SETTINGS: [&str; 5] = [
    "AUTOJOIN_CREDITS",
    "AUTOJOIN_USDCX",
    "AUTOJOIN_ARC20_ETH",
    "AUTOJOIN_ARC20_SOL",
    "AUTOJOIN_ARC20_WBTC",
];

#[test]
fn view_key_requires_explicit_scan_only_configuration() {
    let binary = env!("CARGO_BIN_EXE_autojoin-bot");
    let default_output = Command::new(binary)
        .env_clear()
        .env("ALEO_VIEW_KEY_FILE", "/missing/account.viewkey")
        .output()
        .unwrap();
    let default_error = String::from_utf8(default_output.stderr).unwrap();
    assert!(default_error.contains("autojoin requires ALEO_PRIVATE_KEY_FILE"));

    let mut scan_only = Command::new(binary);
    scan_only
        .env_clear()
        .env("ALEO_VIEW_KEY_FILE", "/missing/account.viewkey");
    for name in AUTOJOIN_SETTINGS {
        scan_only.env(name, "false");
    }
    let scan_output = scan_only.output().unwrap();
    let scan_error = String::from_utf8(scan_output.stderr).unwrap();
    assert!(
        scan_error.contains("failed to securely open key file"),
        "unexpected scan-only error: {scan_error}"
    );
    assert!(!scan_error.contains("autojoin requires ALEO_PRIVATE_KEY_FILE"));
}
