import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";

import { validateTimerDelay } from "./timing.js";

const SCANNER_URL = "https://edge.provable.com/api/scanner";
const PROVER_URL = "https://edge.provable.com/api/prove";
const MAX_VIEW_KEY_FILE_BYTES = 512;

function parseStartBlock(value) {
  if (value === undefined || value.trim() === "") return 0;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
    throw new Error("SCAN_START_BLOCK must be an integer between 0 and 4294967295");
  }
  return parsed;
}

function parseBoolean(value, name, defaultValue) {
  if (value === undefined || value.trim() === "") return defaultValue;
  if (value.toLowerCase() === "true") return true;
  if (value.toLowerCase() === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function parsePositiveInteger(value, name, defaultValue) {
  if (value === undefined || value.trim() === "") return defaultValue;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function parseTimerDelay(value, name, defaultValue) {
  return validateTimerDelay(parsePositiveInteger(value, name, defaultValue), name);
}

export function loadConfig(env = process.env) {
  const network = (env.ALEO_NETWORK ?? "testnet").trim().toLowerCase();
  if (network !== "mainnet" && network !== "testnet") {
    throw new Error("ALEO_NETWORK must be either mainnet or testnet");
  }

  const viewKeyFile = env.ALEO_VIEW_KEY_FILE?.trim();
  const privateKeyFile = env.ALEO_PRIVATE_KEY_FILE?.trim();
  if (Boolean(viewKeyFile) === Boolean(privateKeyFile)) {
    throw new Error("exactly one of ALEO_VIEW_KEY_FILE or ALEO_PRIVATE_KEY_FILE is required");
  }
  const recordStoreFile = env.RECORD_STORE_FILE?.trim();
  const decryptedRecordStoreFile = env.DECRYPTED_RECORD_STORE_FILE?.trim() || undefined;
  if (recordStoreFile && decryptedRecordStoreFile === recordStoreFile) {
    throw new Error("DECRYPTED_RECORD_STORE_FILE must differ from RECORD_STORE_FILE");
  }
  const autojoinCredits = parseBoolean(env.AUTOJOIN_CREDITS, "AUTOJOIN_CREDITS", true);
  const autojoinUsdcx = parseBoolean(env.AUTOJOIN_USDCX, "AUTOJOIN_USDCX", true);
  const autojoinArc20Eth = parseBoolean(env.AUTOJOIN_ARC20_ETH, "AUTOJOIN_ARC20_ETH", true);
  const autojoinArc20Sol = parseBoolean(env.AUTOJOIN_ARC20_SOL, "AUTOJOIN_ARC20_SOL", true);
  const autojoinArc20Wbtc = parseBoolean(env.AUTOJOIN_ARC20_WBTC, "AUTOJOIN_ARC20_WBTC", true);
  const anyArc20 = autojoinArc20Eth || autojoinArc20Sol || autojoinArc20Wbtc;
  const anyAutojoin = autojoinCredits || autojoinUsdcx || anyArc20;
  const delegatedProvingUrl = `${PROVER_URL}/${network}`;
  if (anyAutojoin && !privateKeyFile) {
    throw new Error(
      "autojoin requires ALEO_PRIVATE_KEY_FILE; a view key can only be used when every AUTOJOIN_* setting is false",
    );
  }

  return {
    autojoinCredits,
    autojoinUsdcx,
    autojoinArc20Eth,
    autojoinArc20Sol,
    autojoinArc20Wbtc,
    delegatedProvingUrl,
    autojoinPollIntervalMs: parsePositiveInteger(
      env.AUTOJOIN_POLL_INTERVAL_MS,
      "AUTOJOIN_POLL_INTERVAL_MS",
      5_000,
    ),
    autojoinTimeoutMs: parsePositiveInteger(
      env.AUTOJOIN_TIMEOUT_MS,
      "AUTOJOIN_TIMEOUT_MS",
      300_000,
    ),
    network,
    recordName: env.RECORD_NAME?.trim() || undefined,
    recordProgram: env.RECORD_PROGRAM?.trim() || undefined,
    decryptedRecordStoreFile,
    recordStoreFile,
    recordStorePrivate: parseBoolean(env.RECORD_STORE_PRIVATE, "RECORD_STORE_PRIVATE", true),
    scannerUrl: SCANNER_URL,
    scanSyncPollIntervalMs: parseTimerDelay(
      env.SCAN_SYNC_POLL_INTERVAL_MS,
      "SCAN_SYNC_POLL_INTERVAL_MS",
      5_000,
    ),
    scanSyncTimeoutMs: parseTimerDelay(
      env.SCAN_SYNC_TIMEOUT_MS,
      "SCAN_SYNC_TIMEOUT_MS",
      300_000,
    ),
    startBlock: parseStartBlock(env.SCAN_START_BLOCK),
    keyFile: viewKeyFile || privateKeyFile,
    keyKind: viewKeyFile ? "view" : "private",
  };
}

export function readSecureKeyFile(path) {
  const before = lstatSync(path);
  if (before.isSymbolicLink()) throw new Error("key file must not be a symbolic link");

  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const metadata = fstatSync(fd);
    if (!metadata.isFile()) throw new Error("key file must be a regular file");
    if ((metadata.mode & 0o077) !== 0) {
      throw new Error("key file must not grant group or other access (use chmod 600)");
    }
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
      throw new Error("key file must be owned by the current user");
    }
    if (metadata.size === 0 || metadata.size > MAX_VIEW_KEY_FILE_BYTES) {
      throw new Error(`key file must contain 1-${MAX_VIEW_KEY_FILE_BYTES} bytes`);
    }
    const viewKey = readFileSync(fd, "utf8").trim();
    if (!viewKey) throw new Error("key file is empty");
    return viewKey;
  } finally {
    closeSync(fd);
  }
}

export async function loadSdk(network) {
  return network === "mainnet"
    ? import("@provablehq/sdk/mainnet.js")
    : import("@provablehq/sdk/testnet.js");
}
