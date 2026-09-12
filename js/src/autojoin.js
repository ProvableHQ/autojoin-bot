import { randomBytes } from "node:crypto";
import { cryptoBoxSeal } from "@serenity-kit/noble-sodium";

const CREDITS_PROGRAM = "credits.aleo";
const CREDITS_RECORD = "credits";
const USDCX_PROGRAM = "usdcx_stablecoin.aleo";
const USDCX_RECORD = "Token";

export const JOIN_FAMILIES = Object.freeze({
  credits: Object.freeze({
    name: "credits",
    recordPrograms: Object.freeze({ mainnet: CREDITS_PROGRAM, testnet: CREDITS_PROGRAM }),
    recordName: CREDITS_RECORD,
    programs: Object.freeze({
      mainnet: Object.freeze([
        "autojoin_credits_2_10.aleo",
        "autojoin_credits_11_14.aleo",
        "autojoin_credits_15_16.aleo",
      ]),
      testnet: Object.freeze([
        "autojoin_credits_2_10.aleo",
        "autojoin_credits_11_14.aleo",
        "autojoin_credits_15_16.aleo",
      ]),
    }),
  }),
  usdcx: Object.freeze({
    name: "usdcx",
    recordPrograms: Object.freeze({
      mainnet: USDCX_PROGRAM,
      testnet: "test_usdcx_stablecoin.aleo",
    }),
    recordName: USDCX_RECORD,
    programs: Object.freeze({
      mainnet: Object.freeze([
        "aj_usdcx_stablecoin_2_10.aleo",
        "aj_usdcx_stablecoin_11_14.aleo",
        "aj_usdcx_stablecoin_15_16.aleo",
      ]),
      testnet: Object.freeze([
        "test_aj_usdcx_stablecoin_2_10.aleo",
        "test_aj_usdcx_stablecoin_11_14.aleo",
        "test_aj_usdcx_stablecoin_15_16.aleo",
      ]),
    }),
  }),
});

export function joinCall(family, recordCount, network = "mainnet") {
  if (!Object.values(JOIN_FAMILIES).includes(family)) {
    throw new Error("unknown autojoin record family");
  }
  if (!Number.isInteger(recordCount) || recordCount < 2 || recordCount > 16) {
    throw new Error(`${family.name} join size must be between 2 and 16`);
  }
  const programs = family.programs[network];
  if (!programs) throw new Error("network must be mainnet or testnet");
  const programName = recordCount <= 10
    ? programs[0]
    : recordCount <= 14
      ? programs[1]
      : programs[2];
  return { programName, functionName: `join_${recordCount}` };
}

export function creditsJoinCall(recordCount) {
  return joinCall(JOIN_FAMILIES.credits, recordCount);
}

export function usdcxJoinCall(recordCount, network = "mainnet") {
  return joinCall(JOIN_FAMILIES.usdcx, recordCount, network);
}

export function recordsForFamily(records, family, network = "mainnet") {
  const selected = records.filter((record) => record.program_name === family.recordPrograms[network]
    && record.record_name === family.recordName);
  for (const record of selected) {
    if (typeof record.record_plaintext !== "string" || typeof record.tag !== "string") {
      throw new Error(`owned ${family.name} record is missing plaintext or tag`);
    }
  }
  return selected;
}

export function creditsRecords(records) {
  return recordsForFamily(records, JOIN_FAMILIES.credits);
}

export function canonicalProvingRequest(provingRequest, jobId = randomBytes(16).toString("hex")) {
  const legacy = JSON.parse(provingRequest.toString());
  if (!legacy.authorization) throw new Error("SDK did not build an authorization proving request");
  return {
    broadcast: true,
    job_id: jobId,
    payload: {
      type: "authorization",
      authorization: legacy.authorization,
    },
  };
}

function authHeaders(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function acceptedBroadcast(result) {
  const value = result?.broadcast_result;
  return value?.status === "Accepted" || value?.status === "accepted"
    || (value && typeof value === "object" && "Accepted" in value);
}

export async function submitDelegated({ url, token, request, fetchImpl = fetch }) {
  const headers = authHeaders(token);
  const pubkeyResponse = await fetchImpl(`${url}/pubkey`, { headers });
  if (!pubkeyResponse.ok) {
    throw new Error(`Delegated-prover public-key request failed (HTTP ${pubkeyResponse.status}): ${await pubkeyResponse.text()}`);
  }
  const pubkey = await pubkeyResponse.json();
  const plaintext = new TextEncoder().encode(JSON.stringify(request));
  let ciphertext;
  try {
    ciphertext = cryptoBoxSeal({
      message: plaintext,
      publicKey: Uint8Array.from(Buffer.from(pubkey.public_key, "base64")),
    });
  } finally {
    plaintext.fill(0);
  }
  const cookie = pubkeyResponse.headers.get("set-cookie")?.split(";", 1)[0];
  const response = await fetchImpl(`${url}/prove`, {
    method: "POST",
    headers: {
      ...headers,
      "Content-Type": "application/json",
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body: JSON.stringify({
      key_id: pubkey.key_id,
      ciphertext: Buffer.from(ciphertext).toString("base64"),
    }),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Delegated proving failed (HTTP ${response.status}): ${text}`);
  }
  const result = JSON.parse(text);
  if (!acceptedBroadcast(result)) {
    throw new Error(`Delegated prover did not accept the broadcast: ${JSON.stringify(result.broadcast_result)}`);
  }
  return result;
}

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

export async function consolidateRecords({
  family,
  network = "mainnet",
  sdk,
  privateKey,
  networkUrl,
  proverUrl,
  proverToken,
  initialRecords,
  rescan,
  pollIntervalMs,
  timeoutMs,
  onScan = () => {},
  submit = submitDelegated,
}) {
  let records = initialRecords;
  let joins = 0;
  const manager = new sdk.ProgramManager(networkUrl);

  while (recordsForFamily(records, family, network).length > 1) {
    const available = recordsForFamily(records, family, network);
    const count = Math.min(available.length, 16);
    const selected = available.slice(0, count);
    const selectedTags = new Set(selected.map((record) => record.tag));
    const existingTags = new Set(available.map((record) => record.tag));
    const call = joinCall(family, count, network);
    const provingRequest = await manager.provingRequest({
      ...call,
      inputs: selected.map((record) => record.record_plaintext),
      privateKey,
      priorityFee: 0,
      privateFee: false,
      broadcast: true,
      useFeeMaster: true,
    });
    try {
      await submit({
        url: proverUrl,
        token: proverToken,
        request: canonicalProvingRequest(provingRequest),
      });
    } finally {
      provingRequest.free?.();
    }
    joins += 1;

    const deadline = Date.now() + timeoutMs;
    while (true) {
      records = await rescan();
      onScan(records);
      const current = recordsForFamily(records, family, network);
      const inputsGone = current.every((record) => !selectedTags.has(record.tag));
      const replacementSeen = current.some((record) => !existingTags.has(record.tag));
      if (inputsGone && replacementSeen) break;
      if (Date.now() >= deadline) {
        throw new Error(`timed out waiting for ${call.programName}/${call.functionName} to reach the scanner`);
      }
      await delay(pollIntervalMs);
    }
  }
  return { records, joins, recordsRemaining: recordsForFamily(records, family, network).length };
}

export async function consolidateCredits(options) {
  const result = await consolidateRecords({ ...options, family: JOIN_FAMILIES.credits });
  return { ...result, creditsRemaining: result.recordsRemaining };
}
