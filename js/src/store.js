import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, dirname, join } from "node:path";

const STORE_VERSION = 1;
const MAX_STORE_BYTES = 64 * 1024 * 1024;

function validateOwner(metadata, label) {
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the current user`);
  }
}

function validateParent(path, secure) {
  const parent = dirname(path);
  const metadata = lstatSync(parent);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error("record-store parent must be a real directory, not a symlink");
  }
  if (secure) validateOwner(metadata, "record-store parent");
  if (secure && (metadata.mode & 0o022) !== 0) {
    throw new Error("record-store parent must not be writable by group or others");
  }
  return parent;
}

function validateExistingStore(path, secure) {
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error("record store must be a regular file, not a symlink");
  }
  if (secure) validateOwner(metadata, "record store");
  if (secure && (metadata.mode & 0o077) !== 0) {
    throw new Error("record store must not grant group or other access (use chmod 600)");
  }
  return true;
}

function storedRecord(record, includePlaintext) {
  return Object.fromEntries(Object.entries({
    block_height: record.block_height,
    commitment: record.commitment,
    function_name: record.function_name,
    output_index: record.output_index,
    program_name: record.program_name,
    record_ciphertext: record.record_ciphertext,
    record_plaintext: includePlaintext ? record.record_plaintext : undefined,
    record_name: record.record_name,
    spent: false,
    tag: record.tag,
    transaction_id: record.transaction_id,
    transition_id: record.transition_id,
    transaction_index: record.transaction_index,
    transition_index: record.transition_index,
  }).filter(([, value]) => value !== undefined && value !== null));
}

export function writeRecordStore({
  path,
  network,
  uuid,
  records,
  now = Date.now(),
  includePlaintext = false,
  secure = true,
}) {
  const parent = validateParent(path, secure);
  const exists = validateExistingStore(path, secure);
  if (exists) {
    const current = readRecordStore(path, { secure });
    if (current.network !== network || current.uuid !== uuid
      || current.contains_plaintext !== includePlaintext) {
      throw new Error("record store belongs to a different network, UUID, or record format");
    }
  }
  const snapshot = {
    version: STORE_VERSION,
    network,
    uuid,
    contains_plaintext: includePlaintext,
    updated_at: Math.floor(now / 1000),
    records: records.map((record) => storedRecord(record, includePlaintext)),
  };
  const encoded = `${JSON.stringify(snapshot, null, 2)}\n`;
  const temporary = join(parent, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let fd;
  try {
    fd = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      secure ? 0o600 : 0o644,
    );
    writeFileSync(fd, encoded, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, path);

    const directoryFd = openSync(parent, constants.O_RDONLY);
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(temporary)) unlinkSync(temporary);
    throw error;
  }
}

export function readRecordStore(path, { secure = true } = {}) {
  validateParent(path, secure);
  validateExistingStore(path, secure);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const metadata = fstatSync(fd);
    if (metadata.size > MAX_STORE_BYTES) throw new Error("record store exceeds 64 MiB");
    const store = JSON.parse(readFileSync(fd, "utf8"));
    if (store.version !== STORE_VERSION || !Array.isArray(store.records)) {
      throw new Error("unsupported or invalid record store");
    }
    return store;
  } finally {
    closeSync(fd);
  }
}
