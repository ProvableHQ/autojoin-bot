import { randomBytes } from "node:crypto";
import { cryptoBoxSeal } from "@serenity-kit/noble-sodium";

const CREDITS_PROGRAM = "credits.aleo";
const CREDITS_RECORD = "credits";

export function creditsJoinCall(recordCount) {
  if (!Number.isInteger(recordCount) || recordCount < 2 || recordCount > 16) {
    throw new Error("credits join size must be between 2 and 16");
  }
  const programName = recordCount <= 10
    ? "autojoin_credits_2_10.aleo"
    : recordCount <= 14
      ? "autojoin_credits_11_14.aleo"
      : "autojoin_credits_15_16.aleo";
  return { programName, functionName: `join_${recordCount}` };
}

export function creditsRecords(records) {
  const credits = records.filter((record) => record.program_name === CREDITS_PROGRAM
    && record.record_name === CREDITS_RECORD);
  for (const record of credits) {
    if (typeof record.record_plaintext !== "string" || typeof record.tag !== "string") {
      throw new Error("owned credits record is missing plaintext or tag");
    }
  }
  return credits;
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

export async function consolidateCredits({
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

  while (creditsRecords(records).length > 1) {
    const available = creditsRecords(records);
    const count = Math.min(available.length, 16);
    const selected = available.slice(0, count);
    const selectedTags = new Set(selected.map((record) => record.tag));
    const existingTags = new Set(available.map((record) => record.tag));
    const call = creditsJoinCall(count);
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
      const current = creditsRecords(records);
      const inputsGone = current.every((record) => !selectedTags.has(record.tag));
      const replacementSeen = current.some((record) => !existingTags.has(record.tag));
      if (inputsGone && replacementSeen) break;
      if (Date.now() >= deadline) {
        throw new Error(`timed out waiting for ${call.programName}/${call.functionName} to reach the scanner`);
      }
      await delay(pollIntervalMs);
    }
  }
  return { records, joins, creditsRemaining: creditsRecords(records).length };
}
