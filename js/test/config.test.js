import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadConfig, readSecureKeyFile } from "../src/config.js";

test("loads Edge scanner configuration for either network", () => {
  const config = loadConfig({
    ALEO_VIEW_KEY_FILE: "/secure/account.viewkey",
    ALEO_NETWORK: "mainnet",
    SCAN_START_BLOCK: "42",
    RECORD_STORE_FILE: "/secure/unspent-records.json",
  });

  assert.equal(config.network, "mainnet");
  assert.equal(config.scannerUrl, "https://edge.provable.com/api/scanner");
  assert.equal(config.startBlock, 42);
  assert.equal(config.keyKind, "view");
  assert.equal(config.recordStorePrivate, true);
});

test("rejects invalid network and start block values", () => {
  const base = {
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
  const common = { RECORD_STORE_FILE: "/secure/records.json" };
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
