import assert from "node:assert/strict";
import test from "node:test";
import { cryptoBoxKeyPair, cryptoBoxSealOpen } from "@serenity-kit/noble-sodium";

import {
  canonicalProvingRequest,
  consolidateCredits,
  creditsJoinCall,
  JOIN_FAMILIES,
  consolidateRecords,
  joinCall,
  recordsForFamily,
  submitDelegated,
  usdcxJoinCall,
} from "../src/autojoin.js";

test("maps every supported input count to the deployed credits program", () => {
  assert.deepEqual(creditsJoinCall(2), {
    programName: "autojoin_credits_2_10.aleo",
    functionName: "join_2",
  });
  assert.equal(creditsJoinCall(10).programName, "autojoin_credits_2_10.aleo");
  assert.equal(creditsJoinCall(11).programName, "autojoin_credits_11_14.aleo");
  assert.equal(creditsJoinCall(14).programName, "autojoin_credits_11_14.aleo");
  assert.equal(creditsJoinCall(15).programName, "autojoin_credits_15_16.aleo");
  assert.deepEqual(creditsJoinCall(16), {
    programName: "autojoin_credits_15_16.aleo",
    functionName: "join_16",
  });
  assert.throws(() => creditsJoinCall(1), /between 2 and 16/);
  assert.throws(() => creditsJoinCall(17), /between 2 and 16/);
});

test("uses network-specific USDCx program IDs", () => {
  assert.deepEqual(usdcxJoinCall(2, "mainnet"), {
    programName: "aj_usdcx_stablecoin_2_10.aleo",
    functionName: "join_2",
  });
  assert.equal(
    usdcxJoinCall(11, "testnet").programName,
    "aj_test_usdcx_stablecoin_11_14.aleo",
  );
  assert.equal(
    usdcxJoinCall(16, "testnet").programName,
    "aj_test_usdcx_stablecoin_15_16.aleo",
  );
  const testnetRecord = {
    program_name: "test_usdcx_stablecoin.aleo",
    record_name: "Token",
    record_plaintext: "token record",
    tag: "1field",
  };
  assert.deepEqual(
    recordsForFamily([testnetRecord], JOIN_FAMILIES.usdcx, "testnet"),
    [testnetRecord],
  );
});

test("maps network-specific ARC20 joins and rejects unsupported sizes", () => {
  assert.deepEqual(joinCall(JOIN_FAMILIES.arc20Eth, 15), {
    programName: "main_aj_arc20_2_15.aleo",
    functionName: "join_15",
  });
  assert.throws(() => joinCall(JOIN_FAMILIES.arc20Eth, 16), /between 2 and 15/);
  assert.deepEqual(joinCall(JOIN_FAMILIES.arc20Sol, 2, "testnet"), {
    programName: "test_aj_arc20_2_15.aleo",
    functionName: "join_2",
  });
  assert.equal(JOIN_FAMILIES.arc20Sol.recordPrograms.testnet, "test_arc20_sol.aleo");
  assert.equal(JOIN_FAMILIES.arc20Sol.tokenIdentifiers.testnet, "test_arc20_sol");
});

test("joins 16 ARC20 records as join_15 then join_2 with dynamic dispatch inputs", async () => {
  const calls = [];
  let records = Array.from({ length: 16 }, (_, index) => ({
    program_name: "arc20_eth.aleo",
    record_name: "Token",
    record_plaintext: `token-${index}`,
    tag: `${index}field`,
  }));
  class ProgramManager {
    networkClient = {
      getProgram: async (program) => `program ${program};`,
      getProgramImports: async () => ({ "arc20_multisig_core.aleo": "dependency" }),
    };

    async provingRequest(options) {
      calls.push(options);
      return {
        toString: () => JSON.stringify({ authorization: { requests: [] } }),
        free() {},
      };
    }
  }
  await consolidateRecords({
    family: JOIN_FAMILIES.arc20Eth,
    sdk: { ProgramManager },
    privateKey: {},
    networkUrl: "network",
    proverUrl: "prover",
    initialRecords: records,
    pollIntervalMs: 1,
    timeoutMs: 100,
    submit: async () => {
      const consumed = calls.at(-1).inputs.length - 1;
      records = [...records.slice(consumed), {
        program_name: "arc20_eth.aleo",
        record_name: "Token",
        record_plaintext: "joined",
        tag: `joined-${calls.length}`,
      }];
    },
    rescan: async () => records,
  });
  assert.deepEqual(calls.map(({ programName, functionName, inputs }) => [
    programName,
    functionName,
    inputs.length,
    inputs[0],
  ]), [
    ["main_aj_arc20_2_15.aleo", "join_15", 16, "'arc20_eth'"],
    ["main_aj_arc20_2_15.aleo", "join_2", 3, "'arc20_eth'"],
  ]);
  assert.equal(calls[0].programImports["arc20_eth.aleo"], "program arc20_eth.aleo;");
  assert.equal(calls[0].programImports["arc20_multisig_core.aleo"], "dependency");
});

test("joins 17 records as join_16 followed by join_2", async () => {
  const calls = [];
  let records = Array.from({ length: 17 }, (_, index) => ({
    program_name: "credits.aleo",
    record_name: "credits",
    record_plaintext: `{ owner: aleo1example.private, microcredits: ${index}u64.private, _nonce: 1group.public }`,
    tag: `${index}field`,
  }));
  class ProgramManager {
    async provingRequest(options) {
      calls.push([options.programName, options.functionName, options.inputs.length]);
      return {
        toString: () => JSON.stringify({ authorization: { requests: [] }, broadcast: true }),
        free() {},
      };
    }
  }
  await consolidateCredits({
    sdk: { ProgramManager },
    privateKey: {},
    networkUrl: "network",
    proverUrl: "prover",
    initialRecords: records,
    pollIntervalMs: 1,
    timeoutMs: 100,
    submit: async ({ request }) => {
      assert.equal(request.payload.type, "authorization");
      const count = calls.at(-1)[2];
      records = [...records.slice(count), {
        program_name: "credits.aleo",
        record_name: "credits",
        record_plaintext: "joined",
        tag: `joined-${calls.length}`,
      }];
    },
    rescan: async () => records,
  });
  assert.deepEqual(calls, [
    ["autojoin_credits_15_16.aleo", "join_16", 16],
    ["autojoin_credits_2_10.aleo", "join_2", 2],
  ]);
});

test("consolidates testnet USDCx through the prefixed program", async () => {
  const calls = [];
  let records = ["one", "two"].map((tag) => ({
    program_name: "test_usdcx_stablecoin.aleo",
    record_name: "Token",
    record_plaintext: `{ owner: aleo1example.private, amount: 1u128.private, _nonce: 1group.public }`,
    tag,
  }));
  class ProgramManager {
    async provingRequest(options) {
      calls.push([options.programName, options.functionName]);
      return {
        toString: () => JSON.stringify({ authorization: { requests: [] } }),
        free() {},
      };
    }
  }
  await consolidateRecords({
    family: JOIN_FAMILIES.usdcx,
    network: "testnet",
    sdk: { ProgramManager },
    privateKey: {},
    networkUrl: "network",
    proverUrl: "prover",
    initialRecords: records,
    pollIntervalMs: 1,
    timeoutMs: 100,
    submit: async () => {
      records = [{ ...records[0], tag: "joined" }];
    },
    rescan: async () => records,
  });
  assert.deepEqual(calls, [["aj_test_usdcx_stablecoin_2_10.aleo", "join_2"]]);
});

test("seals canonical JSON for /prove and preserves affinity cookie", async () => {
  const keys = cryptoBoxKeyPair();
  const provingRequest = {
    broadcast: true,
    payload: { type: "authorization", authorization: { requests: [] } },
  };
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push([url, options]);
    if (url.endsWith("/pubkey")) {
      return new Response(JSON.stringify({
        key_id: "key-1",
        public_key: Buffer.from(keys.publicKey).toString("base64"),
      }), {
        status: 200,
        headers: { "set-cookie": "affinity=worker-1; Path=/; Secure" },
      });
    }
    const envelope = JSON.parse(options.body);
    const plaintext = cryptoBoxSealOpen({
      ciphertext: Uint8Array.from(Buffer.from(envelope.ciphertext, "base64")),
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
    });
    assert.deepEqual(JSON.parse(new TextDecoder().decode(plaintext)), provingRequest);
    assert.equal(options.headers.Cookie, "affinity=worker-1");
    return new Response(JSON.stringify({
      transaction: { id: "at1example" },
      broadcast_result: { Accepted: { status_code: 200 } },
    }), { status: 200 });
  };

  await submitDelegated({
    url: "https://prover.example",
    request: provingRequest,
    fetchImpl,
  });
  assert.deepEqual(calls[0][1], {});
  assert.equal(calls[1][0], "https://prover.example/prove");
});

test("canonical proving requests omit job_id", () => {
  const request = canonicalProvingRequest({
    toString: () => JSON.stringify({ authorization: { requests: [] } }),
  });
  assert.equal(request.broadcast, true);
  assert.equal(request.payload.type, "authorization");
  assert.equal("job_id" in request, false);
});
