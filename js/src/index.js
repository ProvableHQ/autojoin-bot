import { loadConfig, loadSdk, readSecureKeyFile } from "./config.js";
import { registerAndFetchUnspentRecords } from "./scanner.js";
import { writeRecordStore } from "./store.js";
import { consolidateCredits } from "./autojoin.js";

const NETWORK_API_URL = "https://api.provable.com/v2";

async function main() {
  const config = loadConfig();
  const sdk = await loadSdk(config.network);
  const encodedKey = readSecureKeyFile(config.keyFile);
  const privateKey = config.keyKind === "private"
    ? sdk.PrivateKey.from_string(encodedKey)
    : undefined;
  const scan = async (filters = {}) => {
    const viewKey = privateKey
      ? sdk.ViewKey.from_private_key(privateKey)
      : sdk.ViewKey.from_string(encodedKey);
    return registerAndFetchUnspentRecords({ sdk, viewKey, ...config, ...filters });
  };

  let result;
  let joinCount = 0;
  try {
    result = await scan();
    if (config.autojoinCredits) {
      const creditsScan = async () => (await scan({
        recordProgram: "credits.aleo",
        recordName: "credits",
      })).records;
      const creditRecords = await creditsScan();
      const proverToken = config.delegatedProvingTokenFile
        ? readSecureKeyFile(config.delegatedProvingTokenFile)
        : undefined;
      const consolidation = await consolidateCredits({
        sdk,
        privateKey,
        networkUrl: NETWORK_API_URL,
        proverUrl: config.delegatedProvingUrl,
        proverToken,
        initialRecords: creditRecords,
        rescan: creditsScan,
        pollIntervalMs: config.autojoinPollIntervalMs,
        timeoutMs: config.autojoinTimeoutMs,
      });
      joinCount = consolidation.joins;
      result = await scan();
    }
  } finally {
    privateKey?.free?.();
  }
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
    creditsJoins: joinCount,
    recordStore: config.recordStoreFile,
    decryptedRecordStore: config.decryptedRecordStoreFile,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
