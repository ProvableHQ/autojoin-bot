import { setTimeout as delay } from "node:timers/promises";

function scannerError(action, result) {
  const status = result.status ? ` (HTTP ${result.status})` : "";
  const message = result.error?.message ?? "unknown scanner error";
  return new Error(`${action} failed${status}: ${message}`);
}

const PAGE_SIZE = 1000;
const TAG_BATCH_SIZE = 1000;

async function waitForScannerSync({ scanner, uuid, viewKey, startBlock, pollIntervalMs, signal }) {
  let reRegistered = false;
  while (true) {
    signal.throwIfAborted();
    const status = await scanner.status(uuid);
    signal.throwIfAborted();
    // The SDK retries /records/owned on 422, but does not retry /status.
    if (!status.ok && status.status === 422 && !reRegistered) {
      const registration = await scanner.register(viewKey, startBlock);
      if (!registration.ok) throw scannerError("Record-scanner re-registration", registration);
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
 * Register an account and return its currently unspent records.
 *
 * The SDK performs the service's one-time /pubkey exchange and sealed-box
 * encryption before POSTing to /register/encrypted. The owned-record request
 * waits for /status to report synced before reading records. Later scans in
 * the same run can skip this startup wait. The result is checked against
 * /records/tags as a final spent-state guard.
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
    const scanner = new sdk.RecordScanner({
      url: scannerUrl,
      viewKeys: [viewKey],
      autoReRegister: true,
      decryptEnabled: true,
      ...(waitForSync ? {
        transport: (request) => fetch(request, { signal: controller.signal }),
      } : {}),
    });

    const registration = await scanner.register(viewKey, startBlock);
    if (!registration.ok) throw scannerError("Record-scanner registration", registration);

    const uuid = registration.data.uuid.toString();
    if (waitForSync) {
      const timer = setTimeout(() => controller.abort(new Error(
        "timed out waiting for initial scanner synchronization; increase SCAN_SYNC_TIMEOUT_MS",
      )), syncTimeoutMs);
      try {
        await waitForScannerSync({
          scanner, uuid, viewKey, startBlock,
          pollIntervalMs: syncPollIntervalMs,
          signal: controller.signal,
        });
      } catch (error) {
        if (controller.signal.aborted) throw controller.signal.reason;
        throw error;
      } finally {
        clearTimeout(timer);
      }
    }
    const records = [];
    for (let page = 0; ; page += 1) {
      const owned = await scanner.owned(
        ownedFilter(uuid, recordProgram, recordName, page),
      );
      if (!owned.ok) throw scannerError("Owned-record fetch", owned);
      records.push(...owned.data);
      if (owned.data.length < PAGE_SIZE) break;
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
