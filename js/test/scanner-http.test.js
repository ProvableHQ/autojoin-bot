import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { loadSdk } from "../src/config.js";
import { registerAndFetchUnspentRecords } from "../src/scanner.js";

test("startup timeout aborts a stalled status body through the real SDK", { timeout: 5_000 }, async () => {
  const sdk = await loadSdk("testnet");
  const privateKey = new sdk.PrivateKey();
  const viewKey = sdk.ViewKey.from_private_key(privateKey);
  const requests = [];
  let freed = false;
  const free = viewKey.free.bind(viewKey);
  viewKey.free = () => { freed = true; free(); };
  const server = createServer(async (request, response) => {
    requests.push(request.url);
    for await (const _chunk of request) { /* Consume the request body. */ }
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/testnet/status") {
      // Send headers and an incomplete body: the timeout must cover body reads.
      response.write("{");
    } else {
      response.writeHead(500);
      response.end("Unexpected record request before sync");
    }
  });
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    await assert.rejects(registerAndFetchUnspentRecords({
      sdk, viewKey,
      scannerUrl: `http://127.0.0.1:${server.address().port}`,
      syncPollIntervalMs: 1,
      syncTimeoutMs: 100,
    }), /timed out waiting for scanner synchronization/);
    assert.deepEqual(requests, ["/testnet/status"]);
    assert.equal(freed, true);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    if (!freed) viewKey.free();
    privateKey.free();
  }
});
