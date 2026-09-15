import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadConfig, readSecureKeyFile } from "../src/config.js";

const SCAN_ONLY = {
  AUTOJOIN_CREDITS: "false",
  AUTOJOIN_USDCX: "false",
  AUTOJOIN_ARC20_ETH: "false",
  AUTOJOIN_ARC20_SOL: "false",
  AUTOJOIN_ARC20_WBTC: "false",
};

test("loads Edge scanner configuration for either network", () => {
  const config = loadConfig({
    ALEO_PRIVATE_KEY_FILE: "/secure/account.privatekey",
    ALEO_NETWORK: "mainnet",
    SCAN_START_BLOCK: "42",
    RECORD_STORE_FILE: "/secure/unspent-records.json",
  });

  assert.equal(config.network, "mainnet");
  assert.equal(config.scannerUrl, "https://edge.provable.com/api/scanner");
  assert.equal(config.delegatedProvingUrl, "https://edge.provable.com/api/prove/mainnet");
  assert.equal(config.startBlock, 42);
  assert.equal(config.keyKind, "private");
  assert.equal(config.autojoinCredits, true);
  assert.equal(config.autojoinUsdcx, true);
  assert.equal(config.autojoinArc20Eth, true);
  assert.equal(config.autojoinArc20Sol, true);
  assert.equal(config.autojoinArc20Wbtc, true);
  assert.equal(config.recordStorePrivate, true);
  assert.equal(config.scanSyncPollIntervalMs, 5_000);
  assert.equal(config.scanSyncTimeoutMs, 300_000);
});

test("record snapshots are optional by default", () => {
  const config = loadConfig({ ALEO_PRIVATE_KEY_FILE: "/secure/account.privatekey" });
  assert.equal(config.recordStoreFile, undefined);
  assert.equal(config.decryptedRecordStoreFile, undefined);
});

test("decrypted snapshots can be enabled without a ciphertext snapshot", () => {
  const config = loadConfig({
    ...SCAN_ONLY,
    ALEO_VIEW_KEY_FILE: "/secure/account.viewkey",
    DECRYPTED_RECORD_STORE_FILE: "/secure/decrypted-records.json",
  });
  assert.equal(config.recordStoreFile, undefined);
  assert.equal(config.decryptedRecordStoreFile, "/secure/decrypted-records.json");
});

test("configures startup sync timing independently of join polling", () => {
  const base = {
    ...SCAN_ONLY,
    ALEO_VIEW_KEY_FILE: "/secure/key",
    RECORD_STORE_FILE: "/secure/records.json",
  };
  const config = loadConfig({
    ...base,
    SCAN_SYNC_POLL_INTERVAL_MS: "25",
    SCAN_SYNC_TIMEOUT_MS: "600000",
  });
  assert.equal(config.scanSyncPollIntervalMs, 25);
  assert.equal(config.scanSyncTimeoutMs, 600_000);
  assert.equal(config.autojoinPollIntervalMs, 5_000);
  assert.equal(config.autojoinTimeoutMs, 300_000);
  for (const name of ["SCAN_SYNC_POLL_INTERVAL_MS", "SCAN_SYNC_TIMEOUT_MS"]) {
    for (const value of ["0", "-1", "1.5", "invalid"]) {
      assert.throws(() => loadConfig({ ...base, [name]: value }), new RegExp(name));
    }
  }
});

test("limits startup sync timing to the Node timer range", () => {
  const base = {
    ...SCAN_ONLY,
    ALEO_VIEW_KEY_FILE: "/secure/key",
    RECORD_STORE_FILE: "/secure/records.json",
  };
  for (const [name, property] of [
    ["SCAN_SYNC_POLL_INTERVAL_MS", "scanSyncPollIntervalMs"],
    ["SCAN_SYNC_TIMEOUT_MS", "scanSyncTimeoutMs"],
  ]) {
    for (const value of [1, 2_147_483_647]) {
      assert.equal(loadConfig({ ...base, [name]: String(value) })[property], value);
    }
    for (const value of ["2147483648", "2592000000"]) {
      assert.throws(() => loadConfig({ ...base, [name]: value }), new RegExp(`${name}.*2147483647`));
    }
  }
});

test("rejects invalid network and start block values", () => {
  const base = {
    ...SCAN_ONLY,
    ALEO_VIEW_KEY_FILE: "/secure/key",
    RECORD_STORE_FILE: "/secure/records.json",
  };
  assert.throws(() => loadConfig({ ...base, ALEO_NETWORK: "devnet" }), /ALEO_NETWORK/);
  assert.throws(() => loadConfig({ ...base, SCAN_START_BLOCK: "-1" }), /SCAN_START_BLOCK/);
  assert.throws(() => loadConfig({ ...base, RECORD_STORE_PRIVATE: "sometimes" }), /true or false/);
});

test("reads only an owner-only regular view-key file", () => {
  const directory = mkdtempSync(join(tmpdir(), "autojoin-view-key-"));
  try {
    const path = join(directory, "account.viewkey");
    writeFileSync(path, "AViewKey1example\n", { mode: 0o600 });
    assert.equal(readSecureKeyFile(path), "AViewKey1example");

    chmodSync(path, 0o640);
    assert.throws(() => readSecureKeyFile(path), /must not grant group or other access/);
    chmodSync(path, 0o600);

    const link = join(directory, "link.viewkey");
    symlinkSync(path, link);
    assert.throws(() => readSecureKeyFile(link), /symbolic link/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("accepts exactly one secure key-file source", () => {
  const common = { ...SCAN_ONLY, RECORD_STORE_FILE: "/secure/records.json" };
  const privateConfig = loadConfig({ ...common, ALEO_PRIVATE_KEY_FILE: "/secure/private" });
  assert.equal(privateConfig.keyKind, "private");
  assert.equal(privateConfig.keyFile, "/secure/private");
  assert.throws(() => loadConfig(common), /exactly one/);
  assert.throws(() => loadConfig({
    ...common,
    ALEO_VIEW_KEY_FILE: "/secure/view",
    ALEO_PRIVATE_KEY_FILE: "/secure/private",
  }), /exactly one/);
});

test("autojoin requires a private key and uses unauthenticated Edge proving", () => {
  const common = {
    RECORD_STORE_FILE: "/secure/records.json",
    AUTOJOIN_CREDITS: "true",
  };
  assert.throws(() => loadConfig({
    ...common,
    ALEO_VIEW_KEY_FILE: "/secure/view",
  }), /requires ALEO_PRIVATE_KEY_FILE/);
  const config = loadConfig({
    ...common,
    ALEO_PRIVATE_KEY_FILE: "/secure/private",
    DELEGATED_PROVING_URL: "https://ignored.example",
    DELEGATED_PROVING_TOKEN_FILE: "/ignored/token",
  });
  assert.equal(config.delegatedProvingUrl, "https://edge.provable.com/api/prove/testnet");
  assert.equal(config.delegatedProvingTokenFile, undefined);

  const usdcx = loadConfig({
    ...SCAN_ONLY,
    AUTOJOIN_USDCX: "true",
    ALEO_PRIVATE_KEY_FILE: "/secure/private",
  });
  assert.equal(usdcx.autojoinUsdcx, true);

  const arc20 = loadConfig({
    ...SCAN_ONLY,
    AUTOJOIN_ARC20_ETH: "true",
    ALEO_NETWORK: "testnet",
    ALEO_PRIVATE_KEY_FILE: "/secure/private",
  });
  assert.equal(arc20.autojoinArc20Eth, true);
});
