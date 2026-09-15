import { setTimeout as delay } from "node:timers/promises";

import { validateTimerDelay } from "./timing.js";

function scannerError(action, result) {
  const status = result.status ? ` (HTTP ${result.status})` : "";
  const message = result.error?.message ?? "unknown scanner error";
  return new Error(`${action} failed${status}: ${message}`);
}

const PAGE_SIZE = 1000;
const TAG_BATCH_SIZE = 1000;

async function registerExpected({ scanner, uuid, viewKey, startBlock }) {
  const registration = await scanner.register(viewKey, startBlock);
  if (!registration.ok) throw scannerError("Record-scanner re-registration", registration);
  const registeredUuid = registration.data?.uuid?.toString();
  if (registeredUuid !== uuid) {
    throw new Error("record scanner returned a different UUID after re-registration");
  }
}

async function waitForScannerSync({ scanner, uuid, viewKey, startBlock, pollIntervalMs, signal }) {
  let reRegistered = false;
  while (true) {
    signal.throwIfAborted();
    const status = await scanner.status(uuid);
    signal.throwIfAborted();
    // The SDK retries /records/owned on 422, but does not retry /status.
    if (!status.ok && status.status === 422 && !reRegistered) {
      // RSS derives the UUID from the view key, so re-registration preserves it.
      await registerExpected({ scanner, uuid, viewKey, startBlock });
      reRegistered = true;
      continue;
    }
    if (!status.ok) throw scannerError("Record-scanner sync status", status);
    if (typeof status.data?.synced !== "boolean") {
      throw new Error("Record-scanner sync status returned an invalid synced flag");
    }
    if (status.data.synced) return;
    await delay(pollIntervalMs, undefined, { signal });
  }
}

async function withSyncTimeout(controller, timeoutMs, operation) {
  const timer = setTimeout(() => controller.abort(new Error(
    "timed out waiting for scanner synchronization; increase SCAN_SYNC_TIMEOUT_MS",
  )), timeoutMs);
  try {
    await operation();
  } catch (error) {
    if (controller.signal.aborted) throw controller.signal.reason;
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function ensureScannerReady(options) {
  const { scanner, uuid, viewKey, startBlock, controller } = options;
  const status = await scanner.status(uuid);
  if (!status.ok && status.status === 422) {
    await registerExpected({ scanner, uuid, viewKey, startBlock });
    await waitForScannerSync({ ...options, signal: controller.signal });
    return;
  }
  if (!status.ok) throw scannerError("Record-scanner registration status", status);
  if (typeof status.data?.synced !== "boolean") {
    throw new Error("Record-scanner registration status returned an invalid synced flag");
  }
  if (!status.data.synced) {
    await waitForScannerSync({ ...options, signal: controller.signal });
  }
  controller.signal.throwIfAborted();
}

function ownedFilter(uuid, recordProgram, recordName, page) {
  const filter = { results_per_page: PAGE_SIZE, page };
  if (recordProgram) filter.programs = [recordProgram];
  if (recordName) filter.records = [recordName];

  return {
    uuid,
    unspent: true,
    filter,
  };
}

/**
 * Ensure an account is registered and return its currently unspent records.
 *
 * The SDK performs the service's one-time /pubkey exchange and sealed-box
 * encryption before POSTing to /register/encrypted when registration is
 * required. The first owned-record request waits for /status to report synced.
 * Later scans skip the startup check, but a 422 during pagination registers,
 * waits for synchronization, and restarts from page zero. The result is
 * checked against /records/tags as a final spent-state guard.
 */
export async function registerAndFetchUnspentRecords({
  sdk,
  viewKey,
  scannerUrl,
  startBlock = 0,
  recordProgram,
  recordName,
  waitForSync = true,
  syncPollIntervalMs = 5_000,
  syncTimeoutMs = 300_000,
}) {
  const controller = new AbortController();
  try {
    validateTimerDelay(syncPollIntervalMs, "SCAN_SYNC_POLL_INTERVAL_MS");
    validateTimerDelay(syncTimeoutMs, "SCAN_SYNC_TIMEOUT_MS");
    const scanner = new sdk.RecordScanner({
      url: scannerUrl,
      viewKeys: [viewKey],
      autoReRegister: false,
      decryptEnabled: true,
      transport: (request) => fetch(request, { signal: controller.signal }),
    });

    const uuid = scanner.computeUUID(viewKey).toString();
    if (waitForSync) {
      await withSyncTimeout(controller, syncTimeoutMs, () => ensureScannerReady({
        scanner, uuid, viewKey, startBlock, controller,
        pollIntervalMs: syncPollIntervalMs,
      }));
    }
    const records = [];
    let page = 0;
    let reRegistered = false;
    while (true) {
      const owned = await scanner.owned(
        ownedFilter(uuid, recordProgram, recordName, page),
      );
      if (!owned.ok && owned.status === 422 && !reRegistered) {
        await withSyncTimeout(controller, syncTimeoutMs, async () => {
          await registerExpected({ scanner, uuid, viewKey, startBlock });
          await waitForScannerSync({
            scanner, uuid, viewKey, startBlock,
            pollIntervalMs: syncPollIntervalMs,
            signal: controller.signal,
          });
        });
        reRegistered = true;
        records.length = 0;
        page = 0;
        continue;
      }
      if (!owned.ok) throw scannerError("Owned-record fetch", owned);
      records.push(...owned.data);
      if (owned.data.length < PAGE_SIZE) break;
      page += 1;
    }

    const tags = [...new Set(records.map((record) => record.tag).filter(Boolean))];
    if (tags.length === 0) {
      return { uuid, records };
    }

    const spent = {};
    for (let offset = 0; offset < tags.length; offset += TAG_BATCH_SIZE) {
      const tagStatus = await scanner.tags(tags.slice(offset, offset + TAG_BATCH_SIZE));
      if (!tagStatus.ok) throw scannerError("Record-tag check", tagStatus);
      Object.assign(spent, tagStatus.data);
    }

    return {
      uuid,
      records: records.filter(
        (record) => !record.tag || spent[record.tag] !== true,
      ),
    };
  } finally {
    controller.abort();
    viewKey.free?.();
  }
}
