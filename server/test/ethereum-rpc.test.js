const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  EthereumRpcError,
  checkEthereumContract,
  validateContractAddress
} = require("../src/ethereum-rpc");

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const ENDPOINT = "https://eth-mainnet.example/v2/credential-must-stay-private";
const ENV = { ETH_RPC_URL: ENDPOINT };

function rpcResponse(id, result) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id, result }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

test("validates Ethereum addresses as exactly 0x plus 40 hexadecimal characters", () => {
  assert.equal(validateContractAddress(ADDRESS), true);
  assert.equal(validateContractAddress(`0x${"A".repeat(40)}`), true);
  assert.equal(validateContractAddress(`0x${"a".repeat(39)}`), false);
  assert.equal(validateContractAddress(`0x${"a".repeat(40)}0`), false);
  assert.equal(validateContractAddress(`0X${"a".repeat(40)}`), false);
  assert.equal(validateContractAddress(42), false);
});

for (const [name, code, expectedStatus] of [
  ["empty code", "0x", "no_bytecode"],
  ["non-empty code", "0x60016000", "bytecode_present"]
]) {
  test(`performs read-only RPC calls and reports ${name} without returning bytecode`, async () => {
    const requests = [];
    const result = await checkEthereumContract(ADDRESS, {
      env: ENV,
      fetchImpl: async (endpoint, init) => {
        requests.push({ endpoint, init, body: JSON.parse(init.body) });
        const { id, method } = requests[requests.length - 1].body;
        const values = {
          eth_chainId: "0x1",
          eth_blockNumber: "0x1234",
          eth_getCode: code
        };
        return rpcResponse(id, values[method]);
      }
    });

    assert.deepEqual(requests.map(({ body }) => body.method).sort(), [
      "eth_blockNumber",
      "eth_chainId",
      "eth_getCode"
    ]);
    const codeRequest = requests.find(({ body }) => body.method === "eth_getCode");
    assert.deepEqual(codeRequest.body.params, [ADDRESS, "latest"]);
    assert.equal(codeRequest.endpoint, ENDPOINT);
    assert.equal(codeRequest.init.method, "POST");
    assert.equal(codeRequest.init.redirect, "error");
    assert.equal(result.address, ADDRESS);
    assert.equal(result.chainId, "0x1");
    assert.equal(result.latestBlock, "0x1234");
    assert.equal(result.codeStatus, expectedStatus);
    if (code !== "0x") {
      assert.ok(!JSON.stringify(result).includes(code.slice(2)));
    }
  });
}

test("normalizes JSON-RPC provider errors without exposing provider messages", async () => {
  await assert.rejects(
    checkEthereumContract(ADDRESS, {
      env: ENV,
      fetchImpl: async (_endpoint, init) => {
        const { id } = JSON.parse(init.body);
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id,
            error: { code: -32000, message: "private provider detail" }
          }),
          { status: 200 }
        );
      }
    }),
    (error) => {
      assert.ok(error instanceof EthereumRpcError);
      assert.equal(error.code, "rpc_error");
      assert.equal(error.providerCode, -32000);
      assert.doesNotMatch(error.message, /private provider detail|credential-must-stay-private/);
      return true;
    }
  );
});

test("normalizes network failures without leaking the configured endpoint", async () => {
  await assert.rejects(
    checkEthereumContract(ADDRESS, {
      env: ENV,
      fetchImpl: async () => {
        throw new Error(`failed ${ENDPOINT}`);
      }
    }),
    (error) => {
      assert.equal(error.code, "network");
      assert.doesNotMatch(error.message, /credential-must-stay-private/);
      return true;
    }
  );
});

test("times out a stalled RPC request", async () => {
  await assert.rejects(
    checkEthereumContract(ADDRESS, {
      env: ENV,
      timeoutMs: 10,
      fetchImpl: async () => new Promise(() => {})
    }),
    (error) => error.code === "timeout"
  );
});

test("rejects malformed JSON, mismatched IDs, and invalid result shapes", async (t) => {
  const cases = [
    {
      name: "malformed JSON",
      fetchImpl: async () => new Response("{")
    },
    {
      name: "mismatched request ID",
      fetchImpl: async (_endpoint, init) =>
        new Response(JSON.stringify({ jsonrpc: "2.0", id: 999, result: "0x1" }))
    },
    {
      name: "invalid block number",
      fetchImpl: async (_endpoint, init) => {
        const { id, method } = JSON.parse(init.body);
        const result = method === "eth_chainId" ? "0x1" : "not-hex";
        return rpcResponse(id, result);
      }
    }
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      await assert.rejects(
        checkEthereumContract(ADDRESS, {
          env: ENV,
          fetchImpl: testCase.fetchImpl
        }),
        (error) => error.code === "bad_response"
      );
    });
  }
});

test("rejects oversized RPC response bodies", async () => {
  await assert.rejects(
    checkEthereumContract(ADDRESS, {
      env: ENV,
      maxResponseBytes: 32,
      fetchImpl: async () => {
        const oversizedBody = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("x".repeat(100)));
            controller.close();
          }
        });
        return new Response(oversizedBody);
      }
    }),
    (error) => error.code === "response_too_large"
  );
});

test("rejects an invalid address before making any RPC request", async () => {
  let called = false;
  await assert.rejects(
    checkEthereumContract("0x1234", {
      env: ENV,
      fetchImpl: async () => {
        called = true;
        return rpcResponse(1, "0x1");
      }
    }),
    (error) => error.code === "invalid_address"
  );
  assert.equal(called, false);
});

test("missing or unsafe RPC configuration fails without exposing its value", async () => {
  await assert.rejects(
    checkEthereumContract(ADDRESS, { env: {} }),
    (error) => error.code === "config_missing"
  );

  const unsafeEndpoint = "http://rpc.example/credential-must-stay-private";
  await assert.rejects(
    checkEthereumContract(ADDRESS, { env: { ETH_RPC_URL: unsafeEndpoint } }),
    (error) => {
      assert.equal(error.code, "config_invalid");
      assert.doesNotMatch(error.message, /credential-must-stay-private/);
      return true;
    }
  );
});
