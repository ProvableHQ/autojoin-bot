function scannerError(action, result) {
  const status = result.status ? ` (HTTP ${result.status})` : "";
  const message = result.error?.message ?? "unknown scanner error";
  return new Error(`${action} failed${status}: ${message}`);
}

const PAGE_SIZE = 1000;
const TAG_BATCH_SIZE = 1000;

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
 * is then checked against /records/tags as a final spent-state guard.
 */
export async function registerAndFetchUnspentRecords({
  sdk,
  viewKey,
  scannerUrl,
  startBlock = 0,
  recordProgram,
  recordName,
}) {
  try {
    const scanner = new sdk.RecordScanner({
      url: scannerUrl,
      viewKeys: [viewKey],
      autoReRegister: true,
      decryptEnabled: true,
    });

    const registration = await scanner.register(viewKey, startBlock);
    if (!registration.ok) throw scannerError("Record-scanner registration", registration);

    const uuid = registration.data.uuid.toString();
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
    viewKey.free?.();
  }
}
