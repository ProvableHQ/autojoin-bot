import assert from "node:assert/strict";
import test from "node:test";

import { registerAndFetchUnspentRecords } from "../src/scanner.js";

function fakeSdk(overrides = {}) {
  const calls = [];

  class RecordScanner {
    constructor(options) { calls.push(["scanner", options]); }
    async register(viewKey, startBlock) {
      calls.push(["register", viewKey, startBlock]);
      return overrides.registration ?? { ok: true, data: { uuid: "123field" } };
    }
    async owned(filter) {
      calls.push(["owned", filter]);
      return overrides.owned ?? {
        ok: true,
        data: [
          { commitment: "one", tag: "1field" },
          { commitment: "two", tag: "2field" },
        ],
      };
    }
    async tags(tags) {
      calls.push(["tags", tags]);
      return overrides.tags ?? { ok: true, data: { "1field": false, "2field": true } };
    }
  }

  return { sdk: { RecordScanner }, calls };
}

test("registers, requests unspent owned records, and rejects tags seen in inputs", async () => {
  const { sdk, calls } = fakeSdk();
  const viewKey = { free: () => calls.push(["free-view-key"]) };
  const result = await registerAndFetchUnspentRecords({
    sdk,
    viewKey,
    scannerUrl: "https://edge.provable.com/api/scanner",
    startBlock: 12,
    recordProgram: "credits.aleo",
    recordName: "credits",
  });

  assert.deepEqual(result, {
    uuid: "123field",
    records: [{ commitment: "one", tag: "1field" }],
  });
  assert.deepEqual(calls[0][1], {
    url: "https://edge.provable.com/api/scanner",
    viewKeys: [viewKey],
    autoReRegister: true,
    decryptEnabled: true,
  });
  assert.deepEqual(calls[1], ["register", viewKey, 12]);
  assert.deepEqual(calls[2], ["owned", {
    uuid: "123field",
    unspent: true,
    filter: {
      programs: ["credits.aleo"],
      records: ["credits"],
      results_per_page: 1000,
      page: 0,
    },
  }]);
  assert.deepEqual(calls[3], ["tags", ["1field", "2field"]]);
  assert.deepEqual(calls.at(-1), ["free-view-key"]);
});

test("surfaces registration failures and destroys account key material", async () => {
  const { sdk, calls } = fakeSdk({
    registration: { ok: false, status: 401, error: { message: "unauthorized" } },
  });
  const viewKey = { free: () => calls.push(["free-view-key"]) };

  await assert.rejects(
    registerAndFetchUnspentRecords({
      sdk,
      viewKey,
      scannerUrl: "https://edge.provable.com/api/scanner",
    }),
    /registration failed \(HTTP 401\): unauthorized/,
  );
  assert.deepEqual(calls.at(-1), ["free-view-key"]);
});
