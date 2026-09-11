import { loadConfig, loadSdk, readSecureKeyFile } from "./config.js";
import { registerAndFetchUnspentRecords } from "./scanner.js";
import { writeRecordStore } from "./store.js";

async function main() {
  const config = loadConfig();
  const sdk = await loadSdk(config.network);
  const encodedKey = readSecureKeyFile(config.keyFile);
  let viewKey;
  if (config.keyKind === "private") {
    const privateKey = sdk.PrivateKey.from_string(encodedKey);
    try {
      viewKey = sdk.ViewKey.from_private_key(privateKey);
    } finally {
      privateKey.free?.();
    }
  } else {
    viewKey = sdk.ViewKey.from_string(encodedKey);
  }
  const result = await registerAndFetchUnspentRecords({ sdk, viewKey, ...config });
  writeRecordStore({
    path: config.recordStoreFile,
    network: config.network,
    uuid: result.uuid,
    records: result.records,
    secure: config.recordStorePrivate,
  });
  if (config.decryptedRecordStoreFile) {
    writeRecordStore({
      path: config.decryptedRecordStoreFile,
      network: config.network,
      uuid: result.uuid,
      records: result.records,
      includePlaintext: true,
      secure: true,
    });
  }

  process.stdout.write(`${JSON.stringify({
    network: config.network,
    uuid: result.uuid,
    recordCount: result.records.length,
    recordStore: config.recordStoreFile,
    decryptedRecordStore: config.decryptedRecordStoreFile,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
