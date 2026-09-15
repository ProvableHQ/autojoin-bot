import assert from "node:assert/strict";
import test from "node:test";

import { registerAndFetchUnspentRecords } from "../src/scanner.js";

function fakeSdk(overrides = {}) {
  const calls = [];

  class RecordScanner {
    constructor(options) { calls.push(["scanner", options]); }
    computeUUID(viewKey) {
      calls.push(["compute-uuid", viewKey]);
      return { toString: () => "123field" };
    }
    async register(viewKey, startBlock) {
      calls.push(["register", viewKey, startBlock]);
      return overrides.registration ?? { ok: true, data: { uuid: "123field" } };
    }
    async status(uuid) {
      calls.push(["status", uuid]);
      return overrides.status?.() ?? { ok: true, data: { synced: true, percentage: 100 } };
    }
    async owned(filter) {
      calls.push(["owned", filter]);
      return (typeof overrides.owned === "function" ? overrides.owned() : overrides.owned) ?? {
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
  const { transport, ...options } = calls[0][1];
  assert.equal(typeof transport, "function");
  assert.deepEqual(options, {
    url: "https://edge.provable.com/api/scanner",
    viewKeys: [viewKey],
    autoReRegister: false,
    decryptEnabled: true,
  });
  assert.deepEqual(calls[1], ["compute-uuid", viewKey]);
  assert.deepEqual(calls[2], ["status", "123field"]);
  assert.deepEqual(calls[3], ["owned", {
    uuid: "123field",
    unspent: true,
    filter: {
      programs: ["credits.aleo"],
      records: ["credits"],
      results_per_page: 1000,
      page: 0,
    },
  }]);
  assert.deepEqual(calls[4], ["tags", ["1field", "2field"]]);
  assert.deepEqual(calls.at(-1), ["free-view-key"]);
});

for (const initialCount of [0, 1]) {
  test(`waits for sync when the initial scanner snapshot would contain ${initialCount} records`, async () => {
    let statusChecks = 0;
    const fullRecords = [{ tag: "a" }, { tag: "b" }, { tag: "c" }];
    const { sdk, calls } = fakeSdk({
      status: () => ({
        ok: true,
        // Percentage can round to 100 while historical work remains.
        data: { synced: ++statusChecks >= 3, percentage: 100 },
      }),
      owned: () => ({
        ok: true,
        data: statusChecks >= 3 ? fullRecords : fullRecords.slice(0, initialCount),
      }),
    });
    const result = await registerAndFetchUnspentRecords({
      sdk,
      viewKey: { free() {} },
      scannerUrl: "https://scanner.example",
      syncPollIntervalMs: 1,
      syncTimeoutMs: 1_000,
    });
    assert.deepEqual(result.records, fullRecords);
    assert.deepEqual(calls.slice(2, 5), Array(3).fill(["status", "123field"]));
    assert.equal(calls[5][0], "owned");
  });
}

for (const count of [0, 1]) {
  test(`accepts ${count} records once the scanner is synchronized`, async () => {
    const records = Array.from({ length: count }, () => ({ tag: "1field" }));
    const { sdk, calls } = fakeSdk({ owned: { ok: true, data: records } });
    const result = await registerAndFetchUnspentRecords({
      sdk,
      viewKey: { free() {} },
      scannerUrl: "https://scanner.example",
    });
    assert.deepEqual(result.records, records);
    assert.equal(calls.filter(([name]) => name === "status").length, 1);
  });
}

test("skips the startup sync wait on subsequent scans", async () => {
  const { sdk, calls } = fakeSdk();
  await registerAndFetchUnspentRecords({
    sdk,
    viewKey: { free() {} },
    scannerUrl: "https://scanner.example",
    waitForSync: false,
  });
  assert.equal(calls.some(([name]) => name === "status"), false);
});

for (const [option, name] of [
  ["syncPollIntervalMs", "SCAN_SYNC_POLL_INTERVAL_MS"],
  ["syncTimeoutMs", "SCAN_SYNC_TIMEOUT_MS"],
]) {
  test(`rejects oversized ${option} before registering and releases the view key`, async () => {
    for (const value of [2_147_483_648, 30 * 24 * 60 * 60 * 1_000]) {
      const { sdk, calls } = fakeSdk();
      await assert.rejects(registerAndFetchUnspentRecords({
        sdk,
        viewKey: { free: () => calls.push(["free-view-key"]) },
        scannerUrl: "https://scanner.example",
        [option]: value,
      }), new RegExp(`${name}.*2147483647`));
      assert.deepEqual(calls, [["free-view-key"]]);
    }
  });
}

test("times out without reading partial records and releases the view key", async () => {
  const { sdk, calls } = fakeSdk({
    status: () => ({ ok: true, data: { synced: false, percentage: 0 } }),
  });
  await assert.rejects(registerAndFetchUnspentRecords({
    sdk,
    viewKey: { free: () => calls.push(["free-view-key"]) },
    scannerUrl: "https://scanner.example",
    syncPollIntervalMs: 1_000,
    syncTimeoutMs: 20,
  }), /timed out waiting for scanner synchronization/);
  assert.equal(calls.some(([name]) => name === "owned"), false);
  assert.deepEqual(calls.at(-1), ["free-view-key"]);
});

test("re-registers once on a 422 sync status using the configured start block", async () => {
  const statuses = [
    { ok: false, status: 422, error: { message: "not registered" } },
    { ok: true, data: { synced: true } },
  ];
  const { sdk, calls } = fakeSdk({ status: () => statuses.shift() });
  const viewKey = { free() {} };
  await registerAndFetchUnspentRecords({
    sdk, viewKey,
    scannerUrl: "https://scanner.example",
    startBlock: 42,
  });
  assert.deepEqual(calls.filter(([name]) => name === "register"), [
    ["register", viewKey, 42],
  ]);
});

for (const [description, status, error] of [
  ["HTTP failure", { ok: false, status: 503, error: { message: "unavailable" } }, /HTTP 503/],
  ["missing sync flag", { ok: true, data: { percentage: 100 } }, /invalid synced flag/],
  ["repeated registration failure", { ok: false, status: 422, error: { message: "not registered" } }, /HTTP 422/],
]) {
  test(`does not read records after a sync status ${description}`, async () => {
    const { sdk, calls } = fakeSdk({ status: () => status });
    await assert.rejects(registerAndFetchUnspentRecords({
      sdk,
      viewKey: { free: () => calls.push(["free-view-key"]) },
      scannerUrl: "https://scanner.example",
    }), error);
    assert.equal(calls.some(([name]) => name === "owned"), false);
    assert.deepEqual(calls.at(-1), ["free-view-key"]);
  });
}

test("surfaces registration failures and destroys account key material", async () => {
  const { sdk, calls } = fakeSdk({
    status: () => ({ ok: false, status: 422, error: { message: "not registered" } }),
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

test("a 422 owned response waits for sync and restarts pagination", async () => {
  const firstPage = Array.from({ length: 1000 }, (_, index) => ({
    commitment: `old-${index}`,
  }));
  const ownedResponses = [
    { ok: true, data: firstPage },
    { ok: false, status: 422, error: { message: "not registered" } },
    { ok: true, data: [{ commitment: "replacement" }] },
  ];
  const statuses = [
    { ok: true, data: { synced: false } },
    { ok: true, data: { synced: true } },
  ];
  const { sdk, calls } = fakeSdk({
    owned: () => ownedResponses.shift(),
    status: () => statuses.shift(),
  });
  const viewKey = { free() {} };

  const result = await registerAndFetchUnspentRecords({
    sdk,
    viewKey,
    scannerUrl: "https://scanner.example",
    waitForSync: false,
    syncPollIntervalMs: 1,
    syncTimeoutMs: 1_000,
  });

  assert.deepEqual(result.records, [{ commitment: "replacement" }]);
  assert.deepEqual(
    calls.filter(([name]) => name === "owned").map(([, filter]) => filter.filter.page),
    [0, 1, 0],
  );
  assert.deepEqual(calls.filter(([name]) => name === "register"), [
    ["register", viewKey, 0],
  ]);
  assert.equal(calls.filter(([name]) => name === "status").length, 2);
});
