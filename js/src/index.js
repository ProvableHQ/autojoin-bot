import { loadConfig, loadSdk, readSecureKeyFile } from "./config.js";
import { registerAndFetchUnspentRecords } from "./scanner.js";
import { writeRecordStore } from "./store.js";
import { JOIN_FAMILIES, consolidateRecords } from "./autojoin.js";

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
  let usdcxJoinCount = 0;
  try {
    result = await scan();
    if (config.autojoinCredits || config.autojoinUsdcx) {
      const proverToken = config.delegatedProvingTokenFile
        ? readSecureKeyFile(config.delegatedProvingTokenFile)
        : undefined;
      const runFamily = async (family) => {
        const familyScan = async () => (await scan({
          recordProgram: family.recordPrograms[config.network],
          recordName: family.recordName,
        })).records;
        return consolidateRecords({
          family,
          network: config.network,
          sdk,
          privateKey,
          networkUrl: NETWORK_API_URL,
          proverUrl: config.delegatedProvingUrl,
          proverToken,
          initialRecords: await familyScan(),
          rescan: familyScan,
          pollIntervalMs: config.autojoinPollIntervalMs,
          timeoutMs: config.autojoinTimeoutMs,
        });
      };
      if (config.autojoinCredits) {
        joinCount = (await runFamily(JOIN_FAMILIES.credits)).joins;
      }
      if (config.autojoinUsdcx) {
        usdcxJoinCount = (await runFamily(JOIN_FAMILIES.usdcx)).joins;
      }
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
    usdcxJoins: usdcxJoinCount,
    recordStore: config.recordStoreFile,
    decryptedRecordStore: config.decryptedRecordStoreFile,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
