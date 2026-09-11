import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";

const SCANNER_URL = "https://edge.provable.com/api/scanner";
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
  if (!recordStoreFile) throw new Error("RECORD_STORE_FILE is required");
  const decryptedRecordStoreFile = env.DECRYPTED_RECORD_STORE_FILE?.trim() || undefined;
  if (decryptedRecordStoreFile === recordStoreFile) {
    throw new Error("DECRYPTED_RECORD_STORE_FILE must differ from RECORD_STORE_FILE");
  }

  return {
    network,
    recordName: env.RECORD_NAME?.trim() || undefined,
    recordProgram: env.RECORD_PROGRAM?.trim() || undefined,
    decryptedRecordStoreFile,
    recordStoreFile,
    recordStorePrivate: parseBoolean(env.RECORD_STORE_PRIVATE, "RECORD_STORE_PRIVATE", true),
    scannerUrl: SCANNER_URL,
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
