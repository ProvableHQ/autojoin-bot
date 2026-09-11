import { loadConfig, loadSdk, readSecureKeyFile } from "./config.js";
import { registerAndFetchUnspentRecords } from "./scanner.js";

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

  process.stdout.write(`${JSON.stringify({ network: config.network, ...result }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
