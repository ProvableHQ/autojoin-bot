import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readRecordStore, writeRecordStore } from "../src/store.js";

test("atomically stores ciphertext metadata without plaintext", () => {
  const directory = mkdtempSync(join(tmpdir(), "autojoin-store-"));
  chmodSync(directory, 0o700);
  try {
    const path = join(directory, "records.json");
    writeRecordStore({
      path,
      network: "testnet",
      uuid: "1field",
      now: 2_000,
      records: [{
        commitment: "commitment",
        record_ciphertext: "record1ciphertext",
        record_plaintext: "secret plaintext",
        program_name: "credits.aleo",
        tag: "2field",
      }],
    });

    assert.deepEqual(readRecordStore(path), {
      version: 1,
      network: "testnet",
      uuid: "1field",
      contains_plaintext: false,
      updated_at: 2,
      records: [{
        commitment: "commitment",
        program_name: "credits.aleo",
        record_ciphertext: "record1ciphertext",
        spent: false,
        tag: "2field",
      }],
    });
    assert.throws(() => writeRecordStore({
      path,
      network: "mainnet",
      uuid: "different-field",
      records: [],
    }), /different network, UUID, or record format/);

    const decryptedPath = join(directory, "decrypted.json");
    writeRecordStore({
      path: decryptedPath,
      network: "testnet",
      uuid: "1field",
      now: 2_000,
      includePlaintext: true,
      records: [{
        record_ciphertext: "record1ciphertext",
        record_plaintext: "secret plaintext",
      }],
    });
    const decrypted = readRecordStore(decryptedPath);
    assert.equal(decrypted.contains_plaintext, true);
    assert.equal(decrypted.records[0].record_plaintext, "secret plaintext");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a symlink record-store target", () => {
  const directory = mkdtempSync(join(tmpdir(), "autojoin-store-"));
  chmodSync(directory, 0o700);
  try {
    const target = join(directory, "target.json");
    const link = join(directory, "records.json");
    symlinkSync(target, link);
    assert.throws(() => writeRecordStore({
      path: link,
      network: "testnet",
      uuid: "1field",
      records: [],
    }), /regular file/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("allows relaxed ciphertext storage when explicitly requested", () => {
  const directory = mkdtempSync(join(tmpdir(), "autojoin-public-store-"));
  chmodSync(directory, 0o777);
  try {
    const path = join(directory, "records.json");
    writeRecordStore({
      path,
      network: "testnet",
      uuid: "1field",
      records: [{ record_ciphertext: "record1ciphertext" }],
      secure: false,
    });
    assert.equal(readRecordStore(path, { secure: false }).records.length, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
