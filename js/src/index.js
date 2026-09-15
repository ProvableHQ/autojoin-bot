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
  let waitForInitialSync = true;
  const scan = async (filters = {}) => {
    const viewKey = privateKey
      ? sdk.ViewKey.from_private_key(privateKey)
      : sdk.ViewKey.from_string(encodedKey);
    const result = await registerAndFetchUnspentRecords({
      sdk, viewKey, ...config, ...filters,
      waitForSync: waitForInitialSync,
      syncPollIntervalMs: config.scanSyncPollIntervalMs,
      syncTimeoutMs: config.scanSyncTimeoutMs,
    });
    waitForInitialSync = false;
    return result;
  };

  let result;
  const joinCounts = {
    credits: 0,
    usdcx: 0,
    arc20Eth: 0,
    arc20Sol: 0,
    arc20Wbtc: 0,
  };
  try {
    const enabledFamilies = [
      [config.autojoinCredits, "credits"],
      [config.autojoinUsdcx, "usdcx"],
      [config.autojoinArc20Eth, "arc20Eth"],
      [config.autojoinArc20Sol, "arc20Sol"],
      [config.autojoinArc20Wbtc, "arc20Wbtc"],
    ].filter(([enabled]) => enabled);
    if (enabledFamilies.length > 0) {
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
          initialRecords: await familyScan(),
          rescan: familyScan,
          pollIntervalMs: config.autojoinPollIntervalMs,
          timeoutMs: config.autojoinTimeoutMs,
        });
      };
      for (const [, familyName] of enabledFamilies) {
        joinCounts[familyName] = (await runFamily(JOIN_FAMILIES[familyName])).joins;
      }
    }
    result = await scan();
  } finally {
    privateKey?.free?.();
  }
  if (config.recordStoreFile) {
    writeRecordStore({
      path: config.recordStoreFile,
      network: config.network,
      uuid: result.uuid,
      records: result.records,
      secure: config.recordStorePrivate,
    });
  }
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
    creditsJoins: joinCounts.credits,
    usdcxJoins: joinCounts.usdcx,
    arc20EthJoins: joinCounts.arc20Eth,
    arc20SolJoins: joinCounts.arc20Sol,
    arc20WbtcJoins: joinCounts.arc20Wbtc,
    recordStore: config.recordStoreFile ?? null,
    decryptedRecordStore: config.decryptedRecordStoreFile ?? null,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
